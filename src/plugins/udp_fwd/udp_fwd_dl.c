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
#include "common.h"
#include "upapp.h"

/* 解析报文头部的五元给信息 */
always_inline int udp_parse_and_lookup_buffer (vlib_buffer_t * b, session_dgram_hdr_t * hdr,
			     u8 is_ip4)
{
	udp_header_t *udp;

	/* udp_local hands us a pointer to the udp data */
	udp = (udp_header_t *) (vlib_buffer_get_current (b) - sizeof (*udp));
	hdr->data_offset = 0;
	hdr->lcl_port = udp->dst_port;
	hdr->rmt_port = udp->src_port;
	hdr->is_ip4 = is_ip4;

	if (is_ip4)
	{
		ip4_header_t *ip4;

		/* TODO: must fix once udp_local does ip options correctly */
		ip4 = (ip4_header_t *) (((u8 *) udp) - sizeof (*ip4));
		ip_set (&hdr->lcl_ip, &ip4->dst_address, 1);
		ip_set (&hdr->rmt_ip, &ip4->src_address, 1);
		hdr->data_length = clib_net_to_host_u16 (ip4->length);
		hdr->data_length -= sizeof (ip4_header_t) + sizeof (udp_header_t);
	}
	else
	{
		ip6_header_t *ip60;

		ip60 = (ip6_header_t *) (((u8 *) udp) - sizeof (*ip60));
		ip_set (&hdr->lcl_ip, &ip60->dst_address, 0);
		ip_set (&hdr->rmt_ip, &ip60->src_address, 0);
		hdr->data_length = clib_net_to_host_u16 (ip60->payload_length);
		hdr->data_length -= sizeof (udp_header_t);
	}

	if (PREDICT_TRUE (!(b->flags & VLIB_BUFFER_NEXT_PRESENT)))
		b->current_length = hdr->data_length;
	else
		b->total_length_not_including_first_buffer = hdr->data_length - b->current_length;
	return 0;
}

/* 下行数据处理函数 */
always_inline uword
udp46_fwd_dl_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
		    vlib_frame_t * frame, u8 is_ip4)
{
	MY_Debug("enter function...");
	u32 n_left_from, *from/*, errors*/, *first_buffer;
	vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
	session_dgram_hdr_t dhdr = {0};
	u8* data;
	int data_len = 0;
	int packet_count = 0;
	/* 存放报文的buffer（数组下标） */
	from = first_buffer = vlib_frame_vector_args (frame);
	/* frme->n_vectors数组长度，也是报文个数 */
	n_left_from = frame->n_vectors;
	packet_count = frame->n_vectors;
	/* 存放报文buffer */
	vlib_get_buffers (vm, from, bufs, n_left_from);

	b = bufs;
	MY_Debug("n_left_from: %d", n_left_from);
	while (n_left_from > 0) 	{
		/* 解析报文的五元组信息 */
		udp_parse_and_lookup_buffer(b[0], &dhdr, is_ip4);
		/* 报文的payload */
		data = (u8*)vlib_buffer_get_current(b[0]);
		data_len = b[0]->current_length; /* 报文payload长度 */
		MY_Debug("len: %d", data_len);
		udp_fwd_main.stat.ipackets ++;
			udp_fwd_main.stat.ibytes += data_len;
		/* 若启用udp_fwd的抓包功能，将保存写放pcap文件中 */
		if (udp_fwd_main.pcap_flag == 1)
			udp_fwd_dl_pcap(data, data_len, dhdr.is_ip4);
		 /* 将报文传递给libupapp.so库 */
		if (libupapp_dl(data, data_len,
            (dgram_hdr_t*)&dhdr.rmt_ip) == data_len) {
			udp_fwd_main.stat.ipackets_succ ++;
			udp_fwd_main.stat.ibytes_succ += data_len;
		}
		b++;
		--n_left_from;
	}
	/* 释放存放报文的buffer，dpdk使用的rte_mbuf也在这里去释放 */
	vlib_buffer_free (vm, first_buffer, frame->n_vectors);
	return packet_count;
}

/* packet trace format function */
static u8 *
format_udp_fwd_dl_trace (u8 * s, va_list * args)
{
#if 0
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  udp_input_trace_t *t = va_arg (*args, udp_input_trace_t *);

  s = format (s, "UDP_INPUT: connection %d, disposition %d, thread %d",
	      t->connection, t->disposition, t->thread_index);
#else
	 s = format (s, "TODO: UDP_fwd_dl trace");
#endif
  return s;
}

static uword
udp4_fwd_dl_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
	    vlib_frame_t * frame)
{
  return udp46_fwd_dl_inline (vm, node, frame, 1);
}

/* 处理下行的节点定义(ipv4)，节点类型：interval */
/* *INDENT-OFF* */
VLIB_REGISTER_NODE(udp4_fwd_dl_node) =
{
  .function = udp4_fwd_dl_fn,
  .name = "udp4-fwd-dl",
  .vector_size = sizeof (u32),
  .format_trace = format_udp_fwd_dl_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
};

static uword
udp6_fwd_dl_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
	    vlib_frame_t * frame)
{
  return udp46_fwd_dl_inline (vm, node, frame, 0);
}

/* 处理下行的节点定义(ipv6)，节点类型：interval */
/* *INDENT-OFF* */
VLIB_REGISTER_NODE(udp6_fwd_dl_node) =
{
  .function = udp6_fwd_dl_fn,
  .name = "udp6-fwd-dl",
  .vector_size = sizeof (u32),
  .format_trace = format_udp_fwd_dl_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
};

/* 将gtpu 2152端口添加到端口列表中。经过这一步骤之后，
 * udp4/6_local_node节点处理后，就会将报文转发到udp4/6_fwd_dl_node节点 */
clib_error_t * udp46_fwd_register_gtpu_port(vlib_main_t * vm)
{
	clib_error_t *error = 0;
	MY_Debug("enter function...");
	if (!udp_is_valid_dst_port (UDP_DST_PORT_GTPU, 1))
		udp_register_dst_port (vm, UDP_DST_PORT_GTPU, udp4_fwd_dl_node.index, /* is_ip4 */ 1);
	else
		printf("[Error][%s:%d] udp port: %d invalid\n", __func__, __LINE__, UDP_DST_PORT_GTPU);
	if ( !udp_is_valid_dst_port (UDP_DST_PORT_GTPU6, 0))
		udp_register_dst_port (vm, UDP_DST_PORT_GTPU6, udp6_fwd_dl_node.index, /* is_ip4 */ 0);
	else
		printf("[Error][%s:%d] udp port: %d invalid\n", __func__, __LINE__, UDP_DST_PORT_GTPU6);
	return error;
}

/* 将gtpu 2152端口从端口列表中移除。*/
clib_error_t * udp46_fwd_unregister_gtpu_port(vlib_main_t * vm)
{
	clib_error_t *error = 0;
	MY_Debug("enter function...");
	udp_unregister_dst_port (vm, UDP_DST_PORT_GTPU, 0);
	udp_unregister_dst_port (vm, UDP_DST_PORT_GTPU6, 0);
	return error;
}


