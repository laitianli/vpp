#include <vlibmemory/api.h>
#include <vlib/vlib.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vppinfra/elog.h>

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/udp/udp.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/session/session.h>

#include "fifo.h"
#include "common.h"
fifo_t			ul_data_node_fifo;
transport_connection_t **vec_tc;
u32 			max_conn_index = 0;
u32 			ip4_next_index = 0;
u32 			ip6_next_index = 0;

static int udp_fwd_ul_xmit_bh(vlib_main_t * vm, vlib_node_runtime_t * node, void** pkt, int count);

/* 此接口由libupapp.so调用，用于上行传递报文
 * 在libupapp.so没有直接调用发送接口，而是将报文先保存到fifo里。
 * 目的：保证操作vpp buffer相关函数都是在vpp线程里调用，同时保证vpp可以批量处理报文
 */
int udp_fwd_ul_xmit(u8* buf, u32 data_len, dgram_hdr_t *dhdr)
{
	struct data_node_head* dnh = (struct data_node_head*)buf;
	udp_fwd_main_t *ufm = &udp_fwd_main;
	if (ufm->create_flag == 0) /* 还没有启用udp_fwd情况下，直接返回 */
		return 0;
	/* 将报文放到fifo列表中 */
	if (fifo_put(&ul_data_node_fifo, (void**)&buf, 1) != 1) {
		dnh->data_node_destructor_fn(dnh);
		return 0;
	}
	return dnh->data_len;
}

/* 上行节点处理函数，功能：从fifo取出报文，再将报文copy到vpp buffer */
static uword
udp_fwd_ul_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
		     vlib_frame_t * frame)
{	
	//udp_fwd_main_t *ufm = &udp_fwd_main;
	void** data_node_arr = NULL;
	/* 上行数据包在fifo中的个数 */
	int max_count = fifo_count(&ul_data_node_fifo);
	int count = 0;
	if (max_count > 0) {
		MY_Debug("fifo max_count: %d\n", max_count);
		/* 分配一个数组 */
		vec_validate(data_node_arr, max_count - 1);
	
		/* 从fifo中取出所有数据并存放到数组里data_node_arr */
		count = fifo_get(&ul_data_node_fifo, data_node_arr, max_count);
		
		/* 将报文copy到vpp buff中，并往ip4/6_lookup_node节点发送。
		 * 在copy完成后，释放libupapp.so使用的mbuf内存
		 */
		udp_fwd_ul_xmit_bh(vm, node, data_node_arr, count);

		/* 释放数组 */
		vec_free(data_node_arr);
	}
	return max_count;
}

/* 上行节点定义，类型为: VLIB_NODE_TYPE_INPUT, 初始状态为DISABLED */
VLIB_REGISTER_NODE (udp_fwd_ul_node) =
{
	.function = udp_fwd_ul_node_fn,
	.name = "udp-fwd-ul",
	.type = VLIB_NODE_TYPE_INPUT,
	.state = VLIB_NODE_STATE_DISABLED,
};
	
/* UL方向的初始化 */
int udp_fwd_ul_init(vlib_main_t* vm)
{
	 /* vec_tc保存上行五元组信息，在初始化时将此数组清空 */
	vec_free(vec_tc);
	 
	/* 传输层初始化，主要是对保存本地端口全局变量(hibash变量)的初始化 */
	transport_init();
	
	/* fifo初始化，此fifo用于临时存放上行libupapp传输到vpp的报文 */
	fifo_init(&ul_data_node_fifo, 2 << 20);
	
	/* 将udp_fwd_ul_node节点状态切换成POLLING，经过此状态切换之前，vpp主线程每循环一次，
	 * udp_fwd_ul_node_fn函数就会执行一次，通过show runtime命令可能查看执行计数 */
	vlib_node_set_state (vm, udp_fwd_ul_node.index, VLIB_NODE_STATE_POLLING);

	/* 对于ul报文，经过此udp_fwd_ul_node处理之后，要传输哪个节点呢？就是通过两个函数配置
	 * 经过此节点处理后的报文，将传输给ip4/6_lookup_node节点处理。
	 * ip4_next_index, ip6_next_index分别为数组下标
	 */
	ip4_next_index = vlib_node_add_next (vm, udp_fwd_ul_node.index, ip4_lookup_node.index);
	ip6_next_index = vlib_node_add_next (vm, udp_fwd_ul_node.index, ip6_lookup_node.index);
	return 0;
}

void udp_fwd_ul_uninit(vlib_main_t* vm)
{
	//udp_fwd_main_t *ufm = &udp_fwd_main;
	vlib_node_set_state (vm, udp_fwd_ul_node.index, VLIB_NODE_STATE_DISABLED);
	fifo_uninit(&ul_data_node_fifo);
}

extern vlib_node_registration_t udp4_fwd_dl_node;
extern vlib_node_registration_t udp6_fwd_dl_node;

static transport_connection_t *tc_lookup_add(vlib_main_t * vm, dgram_hdr_t *pdhdr)
{
	session_endpoint_cfg_t rmt = {0};
	transport_endpoint_cfg_t *tep;
	transport_connection_t *tc = NULL;
	int i = 0;
	if (max_conn_index > 0) {
		for (i = 0; i < max_conn_index; i++) {
			tc = transport_get_half_open (TRANSPORT_PROTO_UDP, (u32)i);
			if (tc->is_ip4) {
				if (tc->rmt_port == pdhdr->rmt_port &&
					tc->rmt_ip.ip4.as_u32 == pdhdr->rmt_ip.ip4.as_u32) {
					/*
					MY_Debug("[%s:%d] tc: 0x%x(%d) dhdr: 0x%x(%d), found tc.", __func__, __LINE__, 
						tc->rmt_ip.ip4.as_u32, ntohs(tc->rmt_port),
						pdhdr->rmt_ip.ip4.as_u32, ntohs(pdhdr->rmt_port));
					*/
					return tc;
				}
			}
			else {
				if (tc->rmt_port == pdhdr->rmt_port &&
					!clib_memcmp(&tc->rmt_ip.ip6, &pdhdr->rmt_ip.ip6, sizeof(ip6_address_t))) {
					return tc;
				}				
			}
		}
	}
	for (i = 0; i < max_conn_index; i++) {
		tc = transport_get_half_open (TRANSPORT_PROTO_UDP, (u32)i);
		if (tc->is_ip4) {
			printf("[%s:%d] tc: 0x%x(%d) dhdr: 0x%x(%d)\n", __func__, __LINE__, 
			tc->rmt_ip.ip4.as_u32, ntohs(tc->rmt_port),
			pdhdr->rmt_ip.ip4.as_u32, ntohs(pdhdr->rmt_port));
		}
	}

	rmt.transport_proto = TRANSPORT_PROTO_UDP;
	rmt.is_ip4 = pdhdr->is_ip4;	/* dst ip config */
	rmt.port = pdhdr->rmt_port;	/*dst port config*/
	ip_copy(&rmt.ip, &pdhdr->rmt_ip, pdhdr->is_ip4);
	//rmt.peer.port = htons(2152);
	//rmt.peer.port = pdhdr->lcl_port;
	//ip_copy(&rmt.peer.ip, &pdhdr->lcl_ip, pdhdr->is_ip4);
	rmt.sw_if_index = ENDPOINT_INVALID_INDEX;
	rmt.peer.sw_if_index = ENDPOINT_INVALID_INDEX;
	rmt.fib_index = 0;
	rmt.peer.fib_index = 0;
	tep = session_endpoint_to_transport_cfg (&rmt);
	int rv = transport_connect(rmt.transport_proto, tep);
	if (rv < 0) {
		printf("[Error][%s:%d] rv: %d\n", __func__, __LINE__, rv);
		return NULL;
	}
	MY_Debug("rv: %d", rv);
	tc = transport_get_half_open (rmt.transport_proto, (u32) rv);
	if (!tc) {
		printf("[Error][%s:%d] transport_get_half_open failed.\n", __func__, __LINE__);
		return NULL;
	}
	if (pdhdr->is_ip4)
		udp_register_dst_port (vm, ntohs(tc->lcl_port), udp4_fwd_dl_node.index, /* is_ip4 */ 1);
	else
		udp_register_dst_port (vm, ntohs(tc->lcl_port), udp6_fwd_dl_node.index, /* is_ip4 */ 0);
	max_conn_index = rv + 1;
	return tc;
}

/* 上行发送接口
 * 功能：1）分配vpp buffer；2）根据目的ip查找对应的transport_connection_t对象；
 *       3）将报文的payload拷贝到vpp buffer；
 *       4）在payload前面添加udp/ip头部信息；
 *       5）将报文发送到一下个节点；
 *		 6）释放mbuf内存；
 */
static int udp_fwd_ul_xmit_bh(vlib_main_t * vm, vlib_node_runtime_t * node, void** pkt, int count)
{
	udp_fwd_main_t *ufm = &udp_fwd_main;
	int err = 0, i = 0;
	dgram_hdr_t *pdhdr;
	u32 data_len = 0;
	u8 *data = NULL, is_ip4 = 1;
	struct data_node_head* dnh = NULL;
	transport_proto_vft_t *transport_vft;
	transport_connection_t *tc;
  	u32 next_index = ~0;
	/* 申请vlib_buffer */
	u8 *buffer_data;
	u32 *tx_buffers = 0;
	u16 n_bufs;	
	vlib_buffer_t *b;
	u32 bi, n_bufs_needed = count;
	/* 根据报文个数分配buffer */
	vec_validate_aligned (tx_buffers, n_bufs_needed - 1, CLIB_CACHE_LINE_BYTES);
	n_bufs = vlib_buffer_alloc (vm, tx_buffers, n_bufs_needed);
	if (PREDICT_FALSE (n_bufs < n_bufs_needed)) {
		printf("[Error][%s:%d] vlib_buffer_alloc(%d) failed\n", __func__, __LINE__, n_bufs_needed);
		if (n_bufs)
			vlib_buffer_free (vm, tx_buffers, n_bufs);
		return -2;
    }
	for (i = 0; i < count; i++) {
		dnh = (struct data_node_head*)pkt[i];
		pdhdr = &dnh->dhdr;
		DUMP_HDR(pdhdr);
		is_ip4 = pdhdr->is_ip4;
		data_len = dnh->data_len;
		data = dnh->data;
		ufm->stat.opackets ++;
		ufm->stat.obytes += dnh->data_len;
		MY_Debug("len: %d", data_len);
		if (udp_fwd_main.pcap_flag == 1) /* 若启用udp_fwd的抓包功能，将保存写放pcap文件中 */
			udp_fwd_ul_pcap(data, data_len, pdhdr->is_ip4);
		/* 根据五元组信息查找transport_connection_t对象，此对象用于填充udp/ip头部 */
		tc = tc_lookup_add(vm, pdhdr);
		if (!tc) {
			ufm->stat.oerrors_full ++;
			err = -1;
			printf("[Error][%s:%d] tc_lookup_add failed.\n", __func__, __LINE__);			
			goto error;
		}

		bi = tx_buffers[i];
      	b = vlib_get_buffer (vm, bi);
		
		/* copy data to vlib buffer */		
		b->error = 0;
  		b->flags = VNET_BUFFER_F_LOCALLY_ORIGINATED;
  		b->current_data = 0;
  		buffer_data = vlib_buffer_make_headroom (b, TRANSPORT_MAX_HDRS_LEN);
		/* 将报文从mbuf拷贝到vpp buffer（也是rte_mbuf） */
		clib_memcpy_fast(buffer_data, data, data_len);
		b->current_length = data_len;
		ufm->stat.opackets_succ ++;
		ufm->stat.obytes_succ += data_len;	
		/* 填充udp/IP头 */
		transport_vft = transport_protocol_get_vft (TRANSPORT_PROTO_UDP);
		transport_vft->push_header (tc, &b, 1);
	}

	/* 发送到下一个节点udp4/6_lookup_node */
	if (is_ip4)
		next_index = ip4_next_index;
	else
		next_index = ip6_next_index;
	MY_Debug("next_index: %d, n->n_next_nodes: %d\n", next_index, node->n_next_nodes);
	vlib_buffer_enqueue_to_single_next(vm, node, tx_buffers, next_index, count);
	goto release;
error:
	vlib_buffer_free (vm, tx_buffers, n_bufs);

release:
	/* 释放数组 */
	vec_free(tx_buffers);
	for (i = 0; i < count; i++) { /* 释放mbuf共享内存 */
		dnh = (struct data_node_head*)pkt[i];
		if (dnh->data_node_destructor_fn)
			dnh->data_node_destructor_fn(dnh);
	}	
	return err;
}

