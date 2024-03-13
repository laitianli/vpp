#include <vnet/vnet.h>
#include <vlibmemory/api.h>
#include <vnet/session/application.h>
#include <vnet/session/application_interface.h>
#include <vnet/session/session.h>
#include <vnet/udp/udp.h>
#include "common.h"

gtpu_client_main_t gtpu_client_main;


static void
gtpu_clients_session_reset_callback (session_t * s)
{
  gtpu_client_main_t *ecm = &gtpu_client_main;
  vnet_disconnect_args_t _a = { 0 }, *a = &_a;

  if (s->session_state == SESSION_STATE_READY)
    clib_warning ("Reset active connection %U", format_session, s, 2);

  a->handle = session_handle (s);
  a->app_index = ecm->app_index;
  vnet_disconnect_session (a);
  return;
}

static int
gtpu_clients_session_create_callback (session_t * s)
{
  return 0;
}

static void
gtpu_clients_session_disconnect_callback (session_t * s)
{
  gtpu_client_main_t *ecm = &gtpu_client_main;
  vnet_disconnect_args_t _a = { 0 }, *a = &_a;
  a->handle = session_handle (s);
  a->app_index = ecm->app_index;
  vnet_disconnect_session (a);
  return;
}

void
gtpu_clients_session_disconnect (session_t * s)
{
  gtpu_client_main_t *ecm = &gtpu_client_main;
  vnet_disconnect_args_t _a = { 0 }, *a = &_a;
  a->handle = session_handle (s);
  a->app_index = ecm->app_index;
  vnet_disconnect_session (a);
}

static int
gtpu_clients_rx_callback (session_t * s)
{
	return 0;
}

int
gtpu_client_add_segment_callback (u32 client_index, u64 segment_handle)
{
  /* New heaps may be added */
  return 0;
}

static int
gtpu_clients_session_connected_callback (u32 app_index, u32 api_context,
					 session_t * s, session_error_t err)
{
	gtpu_client_main_t *ecm = &gtpu_client_main;
	u8 thread_index;

	thread_index = s->thread_index;
	printf("[%s:%d]thread_index:%d vlib_get_thread_index():%ld session_transport_service_type(s):%d, TRANSPORT_SERVICE_CL: %d\n", __func__, __LINE__, 
		thread_index, vlib_get_thread_index (),session_transport_service_type(s), TRANSPORT_SERVICE_CL);
	ASSERT (thread_index == vlib_get_thread_index ()
	  || session_transport_service_type (s) == TRANSPORT_SERVICE_CL);

	if (!ecm->vpp_event_queue[thread_index])
		ecm->vpp_event_queue[thread_index] = session_main_get_vpp_event_queue (thread_index);

#ifndef GTPU_SERVER_USE_TX_FIFO_COPY		
	s->flags |= SESSION_F_UDP_NO_COPY;
#endif
	vec_add1(ecm->connect_session, s);
	vec_add1(ecm->cs_tc, session_get_transport(s));

	return 0;
}


static session_cb_vft_t gtpu_clients = {
	.session_reset_callback = gtpu_clients_session_reset_callback,
	.session_connected_callback = gtpu_clients_session_connected_callback,
	.session_accept_callback = gtpu_clients_session_create_callback,
	.session_disconnect_callback = gtpu_clients_session_disconnect_callback,
	.builtin_app_rx_callback = gtpu_clients_rx_callback,
	.add_segment_callback = gtpu_client_add_segment_callback
};


static void
ec_reset_runtime_config (gtpu_client_main_t *ecm)
{
	ecm->fifo_size = 64 << 10;
	ecm->private_segment_count = 0;
	ecm->private_segment_size = 256 << 20;
	ecm->appns_id = 0;
	vec_validate (ecm->vpp_event_queue, 1);
}


int gtpu_clients_attach(void)
{
	gtpu_client_main_t *ecm = &gtpu_client_main;
	vnet_app_attach_args_t _a, *a = &_a;
	u32 prealloc_fifos;
	u64 options[18];
	int rv;
	ec_reset_runtime_config(ecm);
	clib_memset (a, 0, sizeof (*a));
	clib_memset (options, 0, sizeof (options));

	a->api_client_index = ~0;
	a->name = format (0, "gtpu_client");

	a->session_cb_vft = &gtpu_clients;

	prealloc_fifos = 1;

	options[APP_OPTIONS_ACCEPT_COOKIE] = 0x12345678;
	options[APP_OPTIONS_SEGMENT_SIZE] = ecm->private_segment_size;
	options[APP_OPTIONS_ADD_SEGMENT_SIZE] = ecm->private_segment_size;
	options[APP_OPTIONS_RX_FIFO_SIZE] = ecm->fifo_size;
	options[APP_OPTIONS_TX_FIFO_SIZE] = ecm->fifo_size;
	options[APP_OPTIONS_PRIVATE_SEGMENT_COUNT] = ecm->private_segment_count;
	options[APP_OPTIONS_PREALLOC_FIFO_PAIRS] = prealloc_fifos;
	options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
	//options[APP_OPTIONS_TLS_ENGINE] = ecm->tls_engine;
	options[APP_OPTIONS_PCT_FIRST_ALLOC] = 100;
	//options[APP_OPTIONS_FLAGS] |= ecm->attach_flags;
	if (ecm->appns_id)
	{
	 // options[APP_OPTIONS_NAMESPACE_SECRET] = ecm->appns_secret;
	  a->namespace_id = ecm->appns_id;
	}
	a->options = options;

	if ((rv = vnet_application_attach (a))) {
		printf("[Error][%s:%d]attach returned %d\n", __func__, __LINE__, rv);
		return rv;
	}

	ecm->app_index = a->app_index;
	vec_free (a->name);

	ecm->gtpu_client_attached = 1;

	return 0;
}

static int gtpu_clients_connect_ext(dgram_hdr_t *dhdr, int ci)
{
	gtpu_client_main_t *ecm = &gtpu_client_main;
	vnet_connect_args_t _a = {0}, *a = &_a;
	int rv = 0;
	printf("[Note][%s:%d] ci: %d\n", __func__, __LINE__, ci);
	DUMP_HDR_OPEN(dhdr);
#if 0	
	dhdr->rmt_port = htons(2153);
	dhdr->rmt_ip.ip4.as_u32 = 0x6060606;
#endif	
	a->sep_ext.transport_proto = TRANSPORT_PROTO_UDP;
	a->sep_ext.is_ip4 = dhdr->is_ip4;   /* dst ip config */
	a->sep_ext.port = dhdr->rmt_port;	/*dst port config*/
	ip_copy(&a->sep_ext.ip, &dhdr->rmt_ip, dhdr->is_ip4);
//	a->sep_ext.peer.port = htons(2152); /* source port config*/
#if 0	
	a->sep_ext.peer.is_ip4 = dhdr->is_ip4;
	a->sep_ext.peer.port = dhdr->rmt_port;
	ip_copy(&a->sep_ext.peer.ip, &dhdr->rmt_ip, dhdr->is_ip4);
#endif	
	a->app_index = ecm->app_index;
	a->api_context = ci;
	a->sep_ext.transport_flags = TRANSPORT_CFG_F_CONNECTED;
	a->wrk_map_index = 0;
	rv = vnet_connect(a);
	if (rv) {
		printf("[Error][%s:%d]connect returned: %d\n", __func__, __LINE__, rv);
	}
	return rv;
}

session_t * get_client_session_ext(dgram_hdr_t *dhdr)
{
	gtpu_client_main_t *esm = &gtpu_client_main;
	session_t* s = NULL;
	transport_connection_t * tc = NULL;
	int i = 0;
find_session:
	/*if (vec_len(esm->connect_session) > 0)*/ {
		for (i = 0; i < vec_len(esm->connect_session); i++) {
			s = esm->connect_session[i];
			//tc = esm->cs_tc[i];
			tc = session_get_transport(s);
			if (tc->is_ip4) {
				if (tc->rmt_port == dhdr->rmt_port &&
					tc->rmt_ip.ip4.as_u32 == dhdr->rmt_ip.ip4.as_u32) {
					MY_Debug("[%s:%d] tc: 0x%x(%d) dhdr: 0x%x(%d), found session.", __func__, __LINE__, 
						tc->rmt_ip.ip4.as_u32, ntohs(tc->rmt_port),
						dhdr->rmt_ip.ip4.as_u32, ntohs(dhdr->rmt_port));
					return s;
				}
				/*else {
					tc = session_get_transport(s);
					tc->rmt_port = dhdr->rmt_port;
					ip_copy (&tc->rmt_ip, &dhdr->rmt_ip, dhdr->is_ip4);
					return s;
				}*/
			}
			else {
				if (tc->rmt_port == dhdr->rmt_port &&
					!clib_memcmp(&tc->rmt_ip.ip6, &dhdr->rmt_ip.ip6, sizeof(ip6_address_t))	) {
					return s;
				}
				/*else {
					tc = session_get_transport(s);
					tc->rmt_port = dhdr->rmt_port;
					ip_copy (&tc->rmt_ip, &dhdr->rmt_ip, dhdr->is_ip4);
					return s;
				}*/
			}
		}
	}
	for (i = 0; i < vec_len(esm->connect_session); i++) {
		//tc = esm->cs_tc[i];
		tc = session_get_transport(s);
		if (tc->is_ip4) {
			printf("[%s:%d] tc: 0x%x(%d) dhdr: 0x%x(%d)\n", __func__, __LINE__, 
			tc->rmt_ip.ip4.as_u32, ntohs(tc->rmt_port),
			dhdr->rmt_ip.ip4.as_u32, ntohs(dhdr->rmt_port));
		}
	}
	if (gtpu_clients_connect_ext(dhdr, i + 10) == 0)
		goto find_session;

	return NULL;
}


