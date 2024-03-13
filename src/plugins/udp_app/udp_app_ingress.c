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
#include "load_libudpapp.h"

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

always_inline uword
udp46_app_ingress_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
			vlib_frame_t * frame, u8 is_ip4)
{
	u32 n_left_from, *from, *first_buffer;
	vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
	session_dgram_hdr_t dhdr = {0};
	u8* data;
	int data_len, packet_count = 0;
	from = first_buffer = vlib_frame_vector_args (frame);
	n_left_from = frame->n_vectors;
	packet_count = frame->n_vectors;

	vlib_get_buffers (vm, from, bufs, n_left_from);
	b = bufs;
	
	while (n_left_from > 0)		{
		udp_parse_and_lookup_buffer(b[0], &dhdr, is_ip4);
		data = (u8*)vlib_buffer_get_current(b[0]);
		data_len = b[0]->current_length;
		MY_Debug("len: %d", data_len);
		udpapp_main.stat.ipackets ++;
			udpapp_main.stat.ibytes += data_len;
		if (udpapp_main.pcap_flag == 1)
			udpapp_ingress_pcap(data, data_len, dhdr.is_ip4);
		if (libudpapp_ingress(data, data_len,
			(dgram_hdr_t*)&dhdr.rmt_ip) == data_len) {
			udpapp_main.stat.ipackets_succ ++;
			udpapp_main.stat.ibytes_succ += data_len;
		}
		b++;
		--n_left_from;
	}

	vlib_buffer_free (vm, first_buffer, frame->n_vectors);
	return packet_count;
}

static uword
udp4_app_ingress_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
		vlib_frame_t * frame)
{
	return udp46_app_ingress_inline (vm, node, frame, 1);
}

/* packet trace format function */
static u8 *
format_udpapp_ingress_trace (u8 * s, va_list * args)
{
#if 0
	CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
	CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
	udp_input_trace_t *t = va_arg (*args, udp_input_trace_t *);

	s = format (s, "UDP_INPUT: connection %d, disposition %d, thread %d",
		  t->connection, t->disposition, t->thread_index);
#else
	s = format (s, "TODO: udpapp ingress trace");
#endif
  return s;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE(udp4_app_ingress_node) =
{
	.function = udp4_app_ingress_fn,
	.name = "udp4-app-ingress",
	.vector_size = sizeof (u32),
	.format_trace = format_udpapp_ingress_trace,
	.type = VLIB_NODE_TYPE_INTERNAL,
};

static uword
udp6_app_ingress_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
		vlib_frame_t * frame)
{
	return udp46_app_ingress_inline (vm, node, frame, 0);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE(udp6_app_ingress_node) =
{
	.function = udp6_app_ingress_fn,
	.name = "udp6-app-ingress",
	.vector_size = sizeof (u32),
	.format_trace = format_udpapp_ingress_trace,
	.type = VLIB_NODE_TYPE_INTERNAL,
};

clib_error_t * register_udp46_port(vlib_main_t * vm, u16 udp_port)
{
	clib_error_t *error = 0;
	if (!udp_is_valid_dst_port (udp_port, 1))
		udp_register_dst_port (vm, udp_port, udp4_app_ingress_node.index, /* is_ip4 */ 1);

	if ( !udp_is_valid_dst_port (udp_port, 0))
		udp_register_dst_port (vm, udp_port, udp6_app_ingress_node.index, /* is_ip4 */ 0);

	return error;
}

clib_error_t * unregister_udp46_port(vlib_main_t * vm, u16 udp_port)
{
	clib_error_t *error = 0;

	udp_unregister_dst_port (vm, udp_port, 0);
	udp_unregister_dst_port (vm, udp_port, 0);
	return error;
}


