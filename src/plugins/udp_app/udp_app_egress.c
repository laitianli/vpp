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

#include "udpapp_fifo.h"
#include "common.h"
fifo_t			egress_data_node_fifo;
transport_connection_t **vec_tc;
u32				max_conn_index = 0;
u32				ip4_next_index = 0;
u32				ip6_next_index = 0;

static int udpapp_egress_xmit_bh(vlib_main_t * vm, vlib_node_runtime_t * node, void** pkt, int count);

int udpapp_egress_xmit(u8* buf, u32 data_len, dgram_hdr_t *dhdr)
{
	struct data_node_head* dnh = (struct data_node_head*)buf;
	udpapp_main_t *ufm = &udpapp_main;
	if (ufm->create_flag == 0)
		return 0;
	if (fifo_put(&egress_data_node_fifo, (void**)&buf, 1) != 1) {
		dnh->data_node_destructor_fn(dnh);
		return 0;
	}
	return dnh->data_len;
}

static uword
udpapp_egress_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
			 vlib_frame_t * frame)
{	
	void** data_node_arr = NULL;

	int max_count = fifo_count(&egress_data_node_fifo);
	int count = 0;
	if (max_count > 0) {
		MY_Debug("fifo max_count: %d\n", max_count);
		vec_validate(data_node_arr, max_count - 1);
		count = fifo_get(&egress_data_node_fifo, data_node_arr, max_count);
		udpapp_egress_xmit_bh(vm, node, data_node_arr, count);
		vec_free(data_node_arr);
	}
	return max_count;
}

VLIB_REGISTER_NODE (udpapp_egress_node) =
{
	.function = udpapp_egress_node_fn,
	.name = "udpapp_egress",
	.type = VLIB_NODE_TYPE_INPUT,
	.state = VLIB_NODE_STATE_DISABLED,
};

int udpapp_egress_init(vlib_main_t* vm)
{
	vec_free(vec_tc);
	transport_init();
	
	fifo_init(&egress_data_node_fifo, 2 << 20);
	vlib_node_set_state (vm, udpapp_egress_node.index, VLIB_NODE_STATE_POLLING);

	ip4_next_index = vlib_node_add_next (vm, udpapp_egress_node.index, ip4_lookup_node.index);
	ip6_next_index = vlib_node_add_next (vm, udpapp_egress_node.index, ip6_lookup_node.index);
	return 0;
}

void udpapp_egress_uninit(vlib_main_t* vm)
{
	vlib_node_set_state (vm, udpapp_egress_node.index, VLIB_NODE_STATE_DISABLED);
	fifo_uninit(&egress_data_node_fifo);
}

extern vlib_node_registration_t udp4_app_ingress_node;
extern vlib_node_registration_t udp6_app_ingress_node;

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

	rmt.transport_proto = TRANSPORT_PROTO_UDP;
	rmt.is_ip4 = pdhdr->is_ip4;	/* dst ip config */
	rmt.port = pdhdr->rmt_port;	/*dst port config*/
	ip_copy(&rmt.ip, &pdhdr->rmt_ip, pdhdr->is_ip4);
	/*rmt.peer.port = htons(pdhdr->rmt_port);
	  rmt.peer.port = pdhdr->lcl_port;
	  ip_copy(&rmt.peer.ip, &pdhdr->lcl_ip, pdhdr->is_ip4);
	*/
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
	tc = transport_get_half_open (rmt.transport_proto, (u32) rv);
	if (!tc) {
		printf("[Error][%s:%d] transport_get_half_open failed.\n", __func__, __LINE__);
		return NULL;
	}
	if (pdhdr->is_ip4)
		udp_register_dst_port (vm, ntohs(tc->lcl_port), udp4_app_ingress_node.index, /* is_ip4 */ 1);
	else
		udp_register_dst_port (vm, ntohs(tc->lcl_port), udp6_app_ingress_node.index, /* is_ip4 */ 0);
	max_conn_index = rv + 1;
	return tc;
}

static int udpapp_egress_xmit_bh(vlib_main_t * vm, vlib_node_runtime_t * node, void** pkt, int count)
{
	udpapp_main_t *ufm = &udpapp_main;
	int err = 0, i = 0;
	dgram_hdr_t *pdhdr;
	u32 data_len, next_index = ~0;
	u8* data = NULL;
	u8 is_ip4 = 1;
	struct data_node_head* dnh = NULL;
	transport_proto_vft_t *transport_vft;
	transport_connection_t *tc;		
	u8 *buffer_data;
	u32 *tx_buffers = 0;
	u16 n_bufs;	
	vlib_buffer_t *b;
	u32 bi, n_bufs_needed = count;

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

		pdhdr->rmt_port = htons(ufm->udp_port);
		
		DUMP_HDR(pdhdr);
		is_ip4 = pdhdr->is_ip4;
		data_len = dnh->data_len;
		data = dnh->data;
		ufm->stat.opackets ++;
		ufm->stat.obytes += dnh->data_len;
		MY_Debug("len: %d", data_len);
		if (udpapp_main.pcap_flag == 1)
			udpapp_egress_pcap(data, data_len, pdhdr->is_ip4);

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

		clib_memcpy_fast(buffer_data, data, data_len);
		b->current_length = data_len;
		ufm->stat.opackets_succ ++;
		ufm->stat.obytes_succ += data_len;	

		transport_vft = transport_protocol_get_vft (TRANSPORT_PROTO_UDP);
		transport_vft->push_header (tc, &b, 1);
	}

	if (is_ip4)
		next_index = ip4_next_index;
	else
		next_index = ip6_next_index;
	vlib_buffer_enqueue_to_single_next(vm, node, tx_buffers, next_index, count);
	goto release;
error:
	vlib_buffer_free (vm, tx_buffers, n_bufs);

release:
	vec_free(tx_buffers);
	for (i = 0; i < count; i++) {
		dnh = (struct data_node_head*)pkt[i];
		if (dnh->data_node_destructor_fn)
			dnh->data_node_destructor_fn(dnh);
	}	
	return err;
}

