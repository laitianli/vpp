/*
* Copyright (c) 2017-2019 Cisco and/or its affiliates.
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at:
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#include <vnet/vnet.h>
#include <vlibmemory/api.h>
#include <vnet/session/application.h>
#include <vnet/session/application_interface.h>
#include <vnet/session/session.h>
#include <vnet/udp/udp.h>
#include "fifo.h"
//#include "upapp.h"
#include "common.h"
//#define GTPU_SERVER_USE_RX_FIFO_COPY 1
//#define GTPU_SERVER_USE_TX_FIFO_COPY 1
#define GTPU_CLIENT_NEW_APPLICATION 1
#define ECHO_SERVER_DBG (0)
#define DBG(_fmt, _args...)			\
    if (ECHO_SERVER_DBG) 				\
      clib_warning (_fmt, ##_args)

unsigned char debug_on = 0;


typedef struct
{
	/*
	* Server app parameters
	*/
	svm_msg_q_t **vpp_queue;
	svm_queue_t *vl_input_queue;	/**< Sever's event queue */

	u32 app_index;		/**< Server app index */
	u32 my_client_index;		/**< API client handle */
	u32 node_index;		/**< process node index for event scheduling */

	/*
	* Config params
	*/
	u32 fifo_size;		/**< Fifo size */
	u32 prealloc_fifos;		/**< Preallocate fifos */
	u32 private_segment_count;	/**< Number of private segments  */
	u64 private_segment_size;	/**< Size of private segments  */
	char *server_uri;		/**< Server URI */
    char *debug_flags;

	/*
	* Test state
	*/
	u64 byte_index;
	u32 **rx_retries;
	u8 transport_proto;
	u64 listener_handle;		/**< Session handle of the root listener */
	
	app_session_transport_t at;
	
	vlib_main_t *vlib_main;

	u8 create_flag;
	struct gtpu_stat stat;
	session_t** accept_session;
	session_t** connect_session;
	transport_connection_t ** cs_tc;
#ifdef GTPU_SERVER_USE_RX_FIFO_COPY
	u8 *rx_buf;			/**< Per-thread RX buffer */
	u32 rcv_buffer_size;		/**< Rcv buffer size */
#endif
	fifo_t 			ul_data_node_fifo;
} gtpu_server_main_t;

gtpu_server_main_t gtpu_server_main;

int
gtpu_server_session_accept_callback (session_t * s)
{
	printf("[Note][%s:%d]s->thread_index: %d, session: %p\n", __func__, __LINE__, s->thread_index, s);
	gtpu_server_main_t *esm = &gtpu_server_main;
	esm->vpp_queue[s->thread_index] = session_main_get_vpp_event_queue (s->thread_index);
	s->session_state = SESSION_STATE_READY;
	esm->byte_index = 0;
	ASSERT (vec_len (esm->rx_retries) > s->thread_index);
	vec_validate (esm->rx_retries[s->thread_index], s->session_index);
	esm->rx_retries[s->thread_index][s->session_index] = 0;
#ifndef GTPU_SERVER_USE_RX_FIFO_COPY
	s->flags |= SESSION_F_UDP_NO_COPY;
#endif
	//esm->snd_session = s;
	vec_add1(esm->accept_session, s);
	return 0;
}

void
gtpu_server_session_disconnect_callback (session_t * s)
{
	gtpu_server_main_t *esm = &gtpu_server_main;
	vnet_disconnect_args_t _a = { 0 }, *a = &_a;
	printf("[Note][%s:%d] enter function, s:%p\n", __func__, __LINE__, s);
	a->handle = session_handle (s);
	a->app_index = esm->app_index;
	vnet_disconnect_session (a);
	int i = 0;
	session_t* cs = NULL;
	for (i = 0; i < vec_len(esm->connect_session); i++) {
		cs = esm->connect_session[i];
		if (s == cs) {
			printf("[Note][%s:%d] delete s:%p\n", __func__, __LINE__, s);
			vec_delete(esm->connect_session, 1, i);
			vec_delete(esm->cs_tc, 1, i);
		}
	}
}

void
gtpu_server_session_reset_callback (session_t * s)
{
	printf("[Note][%s:%d] enter function, s:%p\n", __func__, __LINE__, s);
	gtpu_server_main_t *esm = &gtpu_server_main;
	vnet_disconnect_args_t _a = { 0 }, *a = &_a;
	clib_warning ("Reset session %U", format_session, s, 2);
	a->handle = session_handle (s);
	a->app_index = esm->app_index;
	vnet_disconnect_session (a);

	int i = 0;
	session_t* cs = NULL;
	for (i = 0; i < vec_len(esm->connect_session); i++) {
		cs = esm->connect_session[i];
		if (s == cs) {
			printf("[Note][%s:%d] delete s:%p\n", __func__, __LINE__, s);
			vec_delete(esm->connect_session, 1, i);
			vec_delete(esm->cs_tc, 1, i);
		}
	}
}

int
gtpu_server_session_connected_callback (u32 app_index, u32 api_context,
					session_t * s, session_error_t err)
{
	printf("[Note][%s:%d] app_index:%d client session: %p, s->thread_index:%d\n", 
			__func__, __LINE__, app_index, s, s->thread_index);
#ifndef GTPU_CLIENT_NEW_APPLICATION	
	gtpu_server_main_t *esm = &gtpu_server_main;
	esm->vpp_queue[s->thread_index] = session_main_get_vpp_event_queue (s->thread_index);
#ifndef GTPU_SERVER_USE_TX_FIFO_COPY		
	s->flags |= SESSION_F_UDP_NO_COPY;
#endif
	vec_add1(esm->connect_session, s);
	vec_add1(esm->cs_tc, session_get_transport(s));
#endif	
	return 0;
}

int
gtpu_server_add_segment_callback (u32 client_index, u64 segment_handle)
{
	/* New heaps may be added */
	printf("[Note][%s:%d] enter function\n", __func__, __LINE__);
	return 0;
}

static int gtpu_clients_connect (dgram_hdr_t *dhdr, int ci)
{
	gtpu_server_main_t *ecm = &gtpu_server_main;
	vnet_connect_args_t _a = {}, *a = &_a;
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
session_t * get_client_session(dgram_hdr_t *dhdr)
{
	gtpu_server_main_t *esm = &gtpu_server_main;
	session_t* s = NULL;
	transport_connection_t * tc = NULL;
	int i = 0;
find_session:
	/*if (vec_len(esm->connect_session) > 0)*/ {
		for (i = 0; i < vec_len(esm->connect_session); i++) {
			s = esm->connect_session[i];
			tc = esm->cs_tc[i];
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
		tc = esm->cs_tc[i];
		if (tc->is_ip4) {
			printf("[%s:%d] tc: 0x%x(%d) dhdr: 0x%x(%d)\n", __func__, __LINE__, 
			tc->rmt_ip.ip4.as_u32, ntohs(tc->rmt_port),
			dhdr->rmt_ip.ip4.as_u32, ntohs(dhdr->rmt_port));
		}
	}
	if (gtpu_clients_connect(dhdr, i + 100) == 0)
		goto find_session;

	return NULL;
}

static int gtpu_server_xmit(u8* buf, u32 data_len, dgram_hdr_t *dhdr)
{
	struct data_node_head* dnh = (struct data_node_head*)buf;
	gtpu_server_main_t *esm = &gtpu_server_main;
	if (esm->create_flag == 0)
		return 0;
	if (fifo_put(&esm->ul_data_node_fifo, (void**)&buf, 1) != 1) {
		dnh->data_node_destructor_fn(dnh);
		return 0;
	}
	return dnh->data_len;
}
#ifdef GTPU_SERVER_USE_TX_FIFO_COPY
static int _gtpu_server_xmit_bh(void** pkt, int count)
{
	gtpu_server_main_t *esm = &gtpu_server_main;
	session_t * s;
	u32 n_written/*, max_transfer*/;
	int actual_transfer = 0;
	svm_fifo_t *tx_fifo;
	dgram_hdr_t *pdhdr;
	int i = 0;
	struct data_node_head* dnh;
	for (i = 0; i < count; i++) {
		dnh = (struct data_node_head*)pkt[i];
		pdhdr = &dnh->dhdr;

		DUMP_HDR(pdhdr);
		s = get_client_session(pdhdr);
		if (!s) {
			printf("[Error] [%s:%d] session_get is null\n", __func__, __LINE__);
			return -1;
		}
		u32 thread_index = vlib_get_thread_index();
	     if (!s->tx_fifo) {
	        printf("[Error] [%s:%d] session %p tx fifo is null\n", __func__, __LINE__, s);
	        return -1;
	    }
		actual_transfer = dnh->data_len;
		ASSERT (s->thread_index == thread_index);
		esm->stat.opackets ++;
		esm->stat.obytes += dnh->data_len;
		tx_fifo = s->tx_fifo;
		MY_Debug("s->thread_index:%d thread_index: %d, tx_fifo->master_thread_index: %d", 
		 	s->thread_index, thread_index, tx_fifo->master_thread_index);
		ASSERT (tx_fifo->master_thread_index == thread_index);
		
		if (!esm->vpp_queue[s->thread_index])
		{
			svm_msg_q_t *mq;
			mq = session_main_get_vpp_event_queue (s->thread_index);
			esm->vpp_queue[s->thread_index] = mq;
		}
		MY_Debug("before app_send_dgram_raw...");
		n_written = app_send_dgram_raw(tx_fifo, (app_session_transport_t *)pdhdr,
					  esm->vpp_queue[s->thread_index],
					  dnh->data,
					  actual_transfer, SESSION_IO_EVT_TX,
					  1 /* do_evt */ , 0);
		
		MY_Debug("actual_transfer: %d, n_written: %d",	actual_transfer, n_written);
		if (n_written > 0) {
			esm->stat.opackets_succ ++;
			esm->stat.obytes_succ += dnh->data_len;
		}
		else {
			esm->stat.oerrors_full ++;
		}
		if (dnh->data_node_destructor_fn)
			dnh->data_node_destructor_fn(dnh);
	}
	return 0;
}

#else
#ifndef GTPU_CLIENT_NEW_APPLICATION	
static int _gtpu_server_xmit_bh(void** pkt, int count)
{
	gtpu_server_main_t *esm = &gtpu_server_main;
	session_t * s;
	int i = 0;
	u32 n_written, max_enqueue/*, max_transfer*/;
	int actual_transfer = 0;
	svm_fifo_t *tx_fifo;
	dgram_hdr_t *pdhdr;
	int data_len = 0;
	struct data_node_head* dnh = NULL;
	for (i = 0; i < count; i++) {
		dnh = (struct data_node_head*)pkt[i];
		pdhdr = &dnh->dhdr;

		DUMP_HDR(pdhdr);

		s = get_client_session(pdhdr);
		if (!s) {
			printf("[Error] [%s:%d] session_get is null\n", __func__, __LINE__);
			goto error;
		}
		MY_Debug("s=0x%p", s);
		//printf("[%s:%d]s=0x%p\n", __func__, __LINE__, s);
		actual_transfer = sizeof(void*);
		u32 thread_index = vlib_get_thread_index();
	     if (!s->tx_fifo) {
	        printf("[Error] [%s:%d] session %p tx fifo is null\n", __func__, __LINE__, s);
	        goto error;
	    }
		if (s->thread_index != thread_index) {
			printf("[Error][%s:%d]s->thread_index:%d, thread_index: %d\n", 
				__func__, __LINE__, s->thread_index, thread_index);
		}
		ASSERT (s->thread_index == thread_index);
		esm->stat.opackets ++;
		esm->stat.obytes += dnh->data_len;
		tx_fifo = s->tx_fifo;
		ASSERT (tx_fifo->master_thread_index == thread_index);

		max_enqueue = svm_fifo_max_enqueue(tx_fifo);
		MY_Debug("max_enqueue: %d",	max_enqueue);

		if (max_enqueue < sizeof(u32*)) {
			clib_warning ("failed to enqueue self-tap");
			goto error;
		}	
		if (!esm->vpp_queue[s->thread_index]) {
			esm->vpp_queue[s->thread_index] = session_main_get_vpp_event_queue (s->thread_index);
		}
		data_len = dnh->data_len;
		MY_Debug("before app_send_dgram_raw_to_buffer...data len: %d", actual_transfer);
		n_written = app_send_dgram_raw_to_buffer(esm->vlib_main, s, tx_fifo, &esm->at,
					  esm->vpp_queue[s->thread_index],
					  pkt[i],
					  actual_transfer, SESSION_IO_EVT_TX_TO_BUFFER,
					  1 /* do_evt */ , 0);

		MY_Debug("actual_transfer: %d, n_written: %d",	actual_transfer, n_written);
		if (n_written > 0) {
			esm->stat.opackets_succ ++;
			esm->stat.obytes_succ += data_len;
		}
		else {
			esm->stat.oerrors_full ++;
		}
	}
	return 0;

error:
	if (dnh->data_node_destructor_fn)
		dnh->data_node_destructor_fn(dnh);
	return -1;
}
#else
extern gtpu_client_main_t gtpu_client_main;
static int _gtpu_server_xmit_bh(void** pkt, int count)
{
	gtpu_client_main_t *ecm = &gtpu_client_main;
	session_t * s;
	int i = 0;
	u32 n_written, max_enqueue/*, max_transfer*/;
	int actual_transfer = 0;
	svm_fifo_t *tx_fifo;
	dgram_hdr_t *pdhdr;
	int data_len = 0;
	struct data_node_head* dnh = NULL;
	for (i = 0; i < count; i++) {
		dnh = (struct data_node_head*)pkt[i];
		pdhdr = &dnh->dhdr;

		DUMP_HDR(pdhdr);
		s = get_client_session_ext(pdhdr);
		if (!s) {
			printf("[Error] [%s:%d] session_get is null\n", __func__, __LINE__);
			goto error;
		}
		MY_Debug("s=0x%p", s);
		//printf("[%s:%d]s=0x%p\n", __func__, __LINE__, s);
		actual_transfer = sizeof(void*);
		u32 thread_index = vlib_get_thread_index();
	     if (!s->tx_fifo) {
	        printf("[Error] [%s:%d] session %p tx fifo is null\n", __func__, __LINE__, s);
	        goto error;
	    }
		if (s->thread_index != thread_index) {
			printf("[Error][%s:%d]s->thread_index:%d, thread_index: %d\n", 
				__func__, __LINE__, s->thread_index, thread_index);
		}
		ASSERT (s->thread_index == thread_index);
		ecm->stat.opackets ++;
		ecm->stat.obytes += dnh->data_len;
		tx_fifo = s->tx_fifo;
		ASSERT (tx_fifo->master_thread_index == thread_index);

		max_enqueue = svm_fifo_max_enqueue(tx_fifo);
		MY_Debug("max_enqueue: %d",	max_enqueue);

		if (max_enqueue < sizeof(u32*)) {
			clib_warning ("failed to enqueue self-tap");
			goto error;
		}	
		if (!ecm->vpp_event_queue[s->thread_index]) {
			ecm->vpp_event_queue[s->thread_index] = session_main_get_vpp_event_queue (s->thread_index);
		}
		data_len = dnh->data_len;
		MY_Debug("before app_send_dgram_raw_to_buffer...data len: %d", actual_transfer);
		n_written = app_send_dgram_raw_to_buffer(ecm->vlib_main, s, tx_fifo, NULL,
					  ecm->vpp_event_queue[s->thread_index],
					  pkt[i],
					  actual_transfer, SESSION_IO_EVT_TX_TO_BUFFER,
					  1 /* do_evt */ , 0);

		MY_Debug("actual_transfer: %d, n_written: %d",	actual_transfer, n_written);
		if (n_written > 0) {
			ecm->stat.opackets_succ ++;
			ecm->stat.obytes_succ += data_len;
		}
		else {
			ecm->stat.oerrors_full ++;
		}
	}
	return 0;

error:
	if (dnh->data_node_destructor_fn)
		dnh->data_node_destructor_fn(dnh);
	return -1;
}
#endif

#endif
static uword
gtpu_client_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
		     vlib_frame_t * frame)
{	
	gtpu_server_main_t *esm = &gtpu_server_main;
	void** data_node_arr = NULL;
	int max_count = fifo_count(&esm->ul_data_node_fifo);
	int count = 0;
	if (max_count > 0) {
		MY_Debug("fifo max_count: %d\n", max_count);
		vec_validate(data_node_arr, max_count - 1);
		count = fifo_get(&esm->ul_data_node_fifo, data_node_arr, max_count);
		_gtpu_server_xmit_bh(data_node_arr, count);
		vec_free(data_node_arr);
	}
	return 0;
}


VLIB_REGISTER_NODE (gtpu_clients_node) =
{
  .function = gtpu_client_node_fn,
  .name = "gtpu-clients-for-ul",
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_DISABLED,
};

int gtpu_client_init(vlib_main_t* vm)
{
#ifdef GTPU_CLIENT_NEW_APPLICATION
	int ret = 0;
	ret = gtpu_clients_attach();
	if (ret != 0) {
		printf("[Error][%s:%d] gtpu_clients_attach failed.\n", __func__, __LINE__);
		return ret;
	}
#endif	
	gtpu_server_main_t *esm = &gtpu_server_main;
	fifo_init(&esm->ul_data_node_fifo, 32 << 20);
	vlib_node_set_state (vm, gtpu_clients_node.index,
			 VLIB_NODE_STATE_POLLING);
	return 0;
}

void gtpu_client_uninit(vlib_main_t* vm)
{
	gtpu_server_main_t *esm = &gtpu_server_main;
	vlib_node_set_state (vm, gtpu_clients_node.index,
			 VLIB_NODE_STATE_DISABLED);
	fifo_uninit(&esm->ul_data_node_fifo);
}
#ifdef GTPU_SERVER_USE_RX_FIFO_COPY
int gtpu_server_builtin_server_rx_callback (session_t * s)
{
  u32 max_dequeue, max_enqueue, max_transfer;
  int actual_transfer;
  svm_fifo_t *tx_fifo, *rx_fifo;
  gtpu_server_main_t *esm = &gtpu_server_main;
  u32 thread_index = vlib_get_thread_index ();
  app_session_transport_t at;
	if (s->thread_index != thread_index) {
		printf("[%s:%d]s->thread_index:%d thread_index: %d \n", 
				__func__, __LINE__, s->thread_index, thread_index);
	}
  ASSERT (s->thread_index == thread_index);

  rx_fifo = s->rx_fifo;
  tx_fifo = s->tx_fifo;

  ASSERT (rx_fifo->master_thread_index == thread_index);
  ASSERT (tx_fifo->master_thread_index == thread_index);

  max_enqueue = svm_fifo_max_enqueue_prod (tx_fifo);

	session_dgram_pre_hdr_t ph;
	svm_fifo_peek (rx_fifo, 0, sizeof (ph), (u8 *) & ph);
	max_dequeue = ph.data_length - ph.data_offset;
	if (!esm->vpp_queue[s->thread_index])
	{
		svm_msg_q_t *mq;
		mq = session_main_get_vpp_event_queue (s->thread_index);
		esm->vpp_queue[s->thread_index] = mq;
	}
	max_enqueue -= sizeof (session_dgram_hdr_t);


  if (PREDICT_FALSE (max_dequeue == 0))
    return 0;

  /* Number of bytes we're going to copy */
  max_transfer = clib_min (max_dequeue, max_enqueue);

  /* No space in tx fifo */
  if (PREDICT_FALSE (max_transfer == 0))
    {
      /* XXX timeout for session that are stuck */

    rx_event:
      /* Program self-tap to retry */
      if (svm_fifo_set_event (rx_fifo))
	{
	  if (session_send_io_evt_to_thread (rx_fifo,
					     SESSION_IO_EVT_BUILTIN_RX))
	    clib_warning ("failed to enqueue self-tap");

	  vec_validate (esm->rx_retries[s->thread_index], s->session_index);
	  if (esm->rx_retries[thread_index][s->session_index] == 500000)
	    {
	      clib_warning ("session stuck: %U", format_session, s, 2);
	    }
	  if (esm->rx_retries[thread_index][s->session_index] < 500001)
	    esm->rx_retries[thread_index][s->session_index]++;
	}

      return 0;
    }

  vec_validate (esm->rx_buf, max_transfer);
MY_Debug("sizeof(session_dgram_hdr_t): %ld", sizeof(session_dgram_hdr_t));
      actual_transfer = app_recv_dgram_raw (rx_fifo,
					    esm->rx_buf,
					    max_transfer, &at,
					    0 /* don't clear event */ ,
					    0 /* peek */ );
  ASSERT (actual_transfer == max_transfer);
  /* test_bytes (esm, actual_transfer); */
	MY_Debug("len: %d, buf: %s", actual_transfer, esm->rx_buf);

	esm->stat.ipackets ++;
	esm->stat.ibytes += actual_transfer;

	if (libupapp_dl(esm->rx_buf, actual_transfer, 
	    (dgram_hdr_t*)&at) == actual_transfer) {
		esm->stat.ipackets_succ ++;
		esm->stat.ibytes_succ += actual_transfer;
	}

	vec_free(esm->rx_buf);
  	if (PREDICT_FALSE (svm_fifo_max_dequeue_cons (rx_fifo)))
    	goto rx_event;

  return 0;
}

#else
int
gtpu_server_builtin_server_rx_callback(session_t * s)
{
	u32 max_dequeue;
	int ret = 0;
	svm_fifo_t *rx_fifo;
    int max_count_seg = 0;
    int i = 0;
	gtpu_server_main_t *esm = &gtpu_server_main;
	u32 thread_index = vlib_get_thread_index ();
	//app_session_transport_t at;

	ASSERT (s->thread_index == thread_index);
	MY_Debug("enter function.");
	rx_fifo = s->rx_fifo;
	MY_Debug("enter function. s: 0x%p, session_get(): 0x%p", s, 
			session_get(esm->app_index, vlib_get_thread_index ()));
	ASSERT (rx_fifo->master_thread_index == thread_index);
	//svm_fifo_seg_t seg;
	max_dequeue = svm_fifo_max_dequeue(rx_fifo);
    if (max_dequeue < sizeof(svm_fifo_dgram_hdr_seg_t)) {
        printf("[Error][%s:%d] fifo is empty, max_dequeue: %u\n", __func__, __LINE__, max_dequeue);
        return -1;
    }
    
    max_count_seg = max_dequeue / sizeof(svm_fifo_dgram_hdr_seg_t);
    if (max_count_seg > 256) { /* 256 */
        printf("[Debug][%s:%d] max_count_seg=%d\n", __func__, __LINE__, max_count_seg);
    }
	svm_fifo_dgram_hdr_seg_t *dseg= NULL;
    vec_validate(dseg, max_count_seg - 1);
    svm_fifo_dgram_hdr_seg_t *p_dseg = NULL;
    ret = svm_fifo_dequeue(rx_fifo, max_dequeue, (u8 *)dseg);
	if (ret < 0) {
        printf("[Error][%s:%d] svm_fifo_dequeue failed, ret: %d\n", __func__, __LINE__, ret);
		return -1;
    }
    u32 one_seg_len = 0;
    for (i = 0; i < max_count_seg; i++) {
		p_dseg = &dseg[i];
		one_seg_len = p_dseg->seg.len;
		esm->stat.ipackets ++;
		esm->stat.ibytes += one_seg_len;

		/* Number of bytes we're going to copy */
		
		MY_Debug("data len: %d", p_dseg->seg.len);
		if (libupapp_dl(p_dseg->seg.data, one_seg_len, 
            (dgram_hdr_t*)&p_dseg->shdr.rmt_ip) == one_seg_len) {
			esm->stat.ipackets_succ ++;
			esm->stat.ibytes_succ += one_seg_len;
		}
	}
    vec_free(dseg);
	return 0;
}
#endif
static session_cb_vft_t gtpu_server_session_cb_vft = {
	.session_accept_callback = gtpu_server_session_accept_callback,
	.session_disconnect_callback = gtpu_server_session_disconnect_callback,
	.session_connected_callback = gtpu_server_session_connected_callback,
	.add_segment_callback = gtpu_server_add_segment_callback,
	.builtin_app_rx_callback = gtpu_server_builtin_server_rx_callback,
	.session_reset_callback = gtpu_server_session_reset_callback
};

static int
gtpu_server_attach (u8 * appns_id, u64 appns_flags, u64 appns_secret)
{
	gtpu_server_main_t *esm = &gtpu_server_main;
	vnet_app_attach_args_t _a, *a = &_a;
	u64 options[APP_OPTIONS_N_OPTIONS];

	clib_memset (a, 0, sizeof (*a));
	clib_memset (options, 0, sizeof (options));

	a->api_client_index = ~0;
	a->name = format (0, "upapp_gtpu_server");
	a->session_cb_vft = &gtpu_server_session_cb_vft;
	a->options = options;
	a->options[APP_OPTIONS_SEGMENT_SIZE] = esm->private_segment_size;
	a->options[APP_OPTIONS_ADD_SEGMENT_SIZE] = esm->private_segment_size;
	a->options[APP_OPTIONS_RX_FIFO_SIZE] = esm->fifo_size;
	a->options[APP_OPTIONS_TX_FIFO_SIZE] = esm->fifo_size;
	a->options[APP_OPTIONS_PRIVATE_SEGMENT_COUNT] = esm->private_segment_count;
	a->options[APP_OPTIONS_PCT_FIRST_ALLOC] = 100;
	a->options[APP_OPTIONS_PREALLOC_FIFO_PAIRS] =
	esm->prealloc_fifos ? esm->prealloc_fifos : 1;

	a->options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
	if (appns_id) {
		a->namespace_id = appns_id;
		a->options[APP_OPTIONS_FLAGS] |= appns_flags;
		a->options[APP_OPTIONS_NAMESPACE_SECRET] = appns_secret;
	}

	if (vnet_application_attach (a))
	{
		clib_warning ("failed to attach server");
		return -1;
	}
	esm->app_index = a->app_index;
	vec_free (a->name);

	return 0;
}

static int
gtpu_server_detach (void)
{
	gtpu_server_main_t *esm = &gtpu_server_main;
	vnet_app_detach_args_t _da, *da = &_da;
	int rv;
	MY_Debug("enter function.");

	da->app_index = esm->app_index;
	da->api_client_index = ~0;
	rv = vnet_application_detach (da);
	esm->app_index = ~0;
	vec_free(esm->accept_session);
	vec_free(esm->connect_session);
	vec_free(esm->cs_tc);
	return rv;
}


static int
gtpu_server_listen ()
{
	i32 rv;
	gtpu_server_main_t *esm = &gtpu_server_main;
	vnet_listen_args_t _args = { 0 }, *args = &_args;
	MY_Debug("enter function.");

	args->sep_ext.app_wrk_index = 0;
	
	if ((rv = parse_uri (esm->server_uri, &args->sep_ext)))
	{
		return -1;
	}
	args->app_index = esm->app_index;
	printf("[Note][%s:%d] args->sep_ext.transport_proto:%d, TRANSPORT_PROTO_UDP: %d\n", 
			__func__, __LINE__, args->sep_ext.transport_proto, TRANSPORT_PROTO_UDP);
	if (args->sep_ext.transport_proto == TRANSPORT_PROTO_UDP) {
		args->sep_ext.transport_flags = TRANSPORT_CFG_F_CONNECTED;
	}

	rv = vnet_listen (args);
	esm->listener_handle = args->handle;
	if (args->sep_ext.ext_cfg) {
		clib_mem_free (args->sep_ext.ext_cfg);
	}
	return rv;
}

static int
gtpu_server_create (vlib_main_t * vm, u8 * appns_id, u64 appns_flags,
		    u64 appns_secret)
{
	gtpu_server_main_t *esm = &gtpu_server_main;
	vlib_thread_main_t *vtm = vlib_get_thread_main ();
	u32 num_threads;
	int i;
	MY_Debug("enter function.");

	num_threads = 1 /* main thread */  + vtm->n_threads;
	vec_validate (gtpu_server_main.vpp_queue, num_threads - 1);
	vec_validate (esm->rx_retries, num_threads - 1);
	for (i = 0; i < vec_len (esm->rx_retries); i++) {
		vec_validate (esm->rx_retries[i],
			  pool_elts (session_main.wrk[i].sessions));
	}
	if (gtpu_server_attach (appns_id, appns_flags, appns_secret)) {
		clib_warning ("failed to attach server");
		return -1;
	}
	if (gtpu_server_listen()) {
		clib_warning ("failed to start listening");
		if (gtpu_server_detach ())
			clib_warning ("failed to detach");
	  	return -1;
	}
	return 0;
}


static clib_error_t *
gtpu_server_create_command_fn (vlib_main_t * vm, unformat_input_t * input,
			       vlib_cli_command_t * cmd)
{
	session_endpoint_cfg_t sep = SESSION_ENDPOINT_CFG_NULL;
	gtpu_server_main_t *esm = &gtpu_server_main;
	u8 server_uri_set = 0, *appns_id = 0;
	u64 appns_flags = 0, appns_secret = 0;
	char *default_uri = "udp://0.0.0.0/2152";
	int rv, is_stop = 0;
	clib_error_t *error = 0;
	MY_Debug("enter function.");
   
	esm->fifo_size = 256 << 10;
	esm->prealloc_fifos = 32/* 0 */;
	esm->private_segment_count = 0;
	esm->private_segment_size = 512 << 20;
#ifdef GTPU_SERVER_USE_RX_FIFO_COPY
	esm->rcv_buffer_size = 128 << 10;
#endif
	vec_free (esm->server_uri);

	while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
		if (unformat (input, "uri %s", &esm->server_uri))
			server_uri_set = 1;
		else if (unformat (input, "fifo-size %d", &esm->fifo_size))
			esm->fifo_size <<= 10;
		else if (unformat (input, "prealloc-fifos %d", &esm->prealloc_fifos))
			;
		else if (unformat (input, "private-segment-count %d",
			 &esm->private_segment_count))
			;
		else if (unformat (input, "private-segment-size %U",
				 unformat_memory_size, &esm->private_segment_size))
			;
		else if (unformat (input, "appns %_%v%_", &appns_id))
			;
		else if (unformat (input, "all-scope"))
			appns_flags |= (APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE
					| APP_OPTIONS_FLAGS_USE_LOCAL_SCOPE);
		else if (unformat (input, "local-scope"))
			appns_flags |= APP_OPTIONS_FLAGS_USE_LOCAL_SCOPE;
		else if (unformat (input, "global-scope"))
			appns_flags |= APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;
		else if (unformat (input, "secret %lu", &appns_secret))
			;
		else if (unformat (input, "stop"))
			is_stop = 1;
		else
		{
			error = clib_error_return (0, "failed: unknown input `%U'",
					     format_unformat_error, input);
			goto cleanup;
		}
	}

	if (is_stop)
	{
		if (esm->app_index == (u32) ~ 0)
		{
			clib_warning ("server not running");
			error = clib_error_return (0, "failed: server not running");
			goto cleanup;
		}
		rv = gtpu_server_detach();
		if (rv)
		{
			clib_warning ("failed: detach");
			error = clib_error_return (0, "failed: server detach %d", rv);
			goto cleanup;
		}
        esm->create_flag = 0;
		gtpu_client_uninit(vm);
		
        /* todo: unload libupapp */
        printf("[Note] begin uninit libupapp.so...");
        libuapp_uninit();
        printf("success!\n[Note] begin unload libupapp.so...");
        unlod_libupapp();
        printf("success!\n");
		goto cleanup;
	}
    
    if (esm->create_flag == 1) {
        vlib_cli_output (vm, "[Note] libupapp.so has loaded, return it!");
        goto cleanup;
    }
	vnet_session_enable_disable(vm, 1);

	if (!server_uri_set)
	{
		clib_warning ("No uri provided! Using default: %s", default_uri);
		esm->server_uri = (char *) format (0, "%s%c", default_uri, 0);
	}

	if ((rv = parse_uri ((char *) esm->server_uri, &sep)))
	{
		error = clib_error_return (0, "Uri parse error: %d", rv);
		goto cleanup;
	}
	esm->transport_proto = sep.transport_proto;

	rv = gtpu_server_create(vm, appns_id, appns_flags, appns_secret);
	if (rv)
	{
		vec_free (esm->server_uri);
		error = clib_error_return (0, "failed: server_create returned %d", rv);
		goto cleanup;
	}
	rv = gtpu_client_init(vm);
	if (rv) {
		gtpu_server_detach();
		vec_free (esm->server_uri);
		error = clib_error_return (0, "failed: client init returned %d", rv);
		goto cleanup;
	}
	load_libupapp();
	libuapp_init();
	libupapp_set_ul_fun(gtpu_server_xmit);
	esm->create_flag = 1;
	cleanup:
		vec_free (appns_id);

	return error;
}


VLIB_CLI_COMMAND (gtpu_server_create_command, static) =
{
  .path = "upapp gtpu server",
  .short_help = "upapp gtpu server [echo] [fifo-size <mbytes>]"
      "[rcv-buf-size <bytes>][prealloc-fifos <count>]"
      "[private-segment-count <count>][private-segment-size <bytes[m|g]>]"
      "[uri <udp://ip/port>]",
  .function = gtpu_server_create_command_fn,
};

static clib_error_t *
gtpu_server_show_command_fn (vlib_main_t * vm, unformat_input_t * input,
			       vlib_cli_command_t * cmd)
{
	clib_error_t *error = 0;
	gtpu_server_main_t *esm = &gtpu_server_main;
	if (esm->create_flag != 1) {		
		error = clib_error_return (0, "failed: gtpu server does not created!");
		goto end;
	}
	
	while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
		if (unformat (input, "stat"))
		{
			vlib_cli_output (vm, "ipacket: %-16Lu ipacket_succ: %-16Lu ibytes: %-16Lu ibytes_succ: %-16Lu", 
					esm->stat.ipackets, esm->stat.ipackets_succ,
					esm->stat.ibytes, esm->stat.ibytes_succ);
			vlib_cli_output (vm, "opacket: %-16Lu opacket_succ: %-16Lu obytes: %-16Lu obytes_succ: %-16Lu", 
					esm->stat.opackets, esm->stat.opackets_succ,
					esm->stat.obytes, esm->stat.obytes_succ);
			vlib_cli_output (vm, "ierrors: %-16Lu oerrors: %-16Lu oerrors_full: %-16Lu", 
					esm->stat.ierrors, esm->stat.oerrors,
					esm->stat.oerrors_full);
		}
		else
		{
			error = clib_error_return (0, "failed: unknown input `%U'",
					     format_unformat_error, input);
			goto end;
		}
	}
end:	
	return error;
}


VLIB_CLI_COMMAND (gtpu_server_show_stat_command, static) =
{
  .path = "upapp gtpu server show",
  .short_help = "upapp gtpu server show [stat]",
  .function = gtpu_server_show_command_fn,
};

#define LIBUPAPP_IOCTL_CMD_DEBUG 	0x001
#define LIBUPAPP_IOCTL_CMD_OPEN_SNED 0x002
typedef struct _client_packet_info {
	int count;
	int length;
	dgram_hdr_t hdr;
}client_packet_info_t;

static clib_error_t *
gtpu_server_ioctl_command_fn (vlib_main_t * vm, unformat_input_t * input,
			       vlib_cli_command_t * cmd)
{
	clib_error_t *error = 0;
	gtpu_server_main_t *esm = &gtpu_server_main;
	if (esm->create_flag != 1) {		
		error = clib_error_return (0, "failed: gtpu server does not created!");
		goto end;
	}
	
	while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
		int client_first_send_count = 0;
		int one_packet_length = 0;
		char* dst_ip_port = 0;
		if (unformat (input, "client_first %d %d %s", 
			&client_first_send_count, &one_packet_length, &dst_ip_port))
		{
			client_packet_info_t cinfo = {0};
			cinfo.count = client_first_send_count;
			cinfo.length = one_packet_length;
			u16 port = 0;
			unformat_input_t dst_ip_port_input, *dst_p = &dst_ip_port_input;
			{
				unformat_init_string (dst_p, dst_ip_port, strlen(dst_ip_port));
				if (unformat(dst_p, "dst:%U/%d",
			  		unformat_ip4_address, &cinfo.hdr.rmt_ip.ip4, &port)) {
			  		printf("[Note][%s:%d] dst port: %d\n", __func__, __LINE__, port);
			  		cinfo.hdr.rmt_port = htons(port);
			  	}
				cinfo.hdr.is_ip4 = 1;
			}
			vec_free(dst_ip_port);
			libupapp_ioctl(LIBUPAPP_IOCTL_CMD_OPEN_SNED, (void*)&cinfo);
		}
		else if (unformat (input, "debug %s", &esm->debug_flags)) {
			if (!clib_strncmp(esm->debug_flags, "on", strlen("on")))
				debug_on = 1;
			else
				debug_on = 0;
			libupapp_ioctl(LIBUPAPP_IOCTL_CMD_DEBUG, (void*)&debug_on);
		}
		else
		{
			error = clib_error_return (0, "failed: unknown input `%U'",
					     format_unformat_error, input);
			goto end;
		}
	}
end:	
	return error;
}


VLIB_CLI_COMMAND (gtpu_server_ioctl_command, static) =
{
  .path = "upapp gtpu server ioctl",
  .short_help = "upapp gtpu server ioctl"
  	"[debug on|off]"
  	"[client_first <count> <len> <dst:ip/port>]",
  .function = gtpu_server_ioctl_command_fn,
};


clib_error_t *
gtpu_server_main_init (vlib_main_t * vm)
{
  gtpu_server_main_t *esm = &gtpu_server_main;
  memset(esm, 0, sizeof(gtpu_server_main_t));
  esm->my_client_index = ~0;
  esm->vlib_main = vm;  
  return 0;
}

VLIB_INIT_FUNCTION (gtpu_server_main_init);

/*
* fd.io coding-style-patch-verification: ON
*
* Local Variables:
* eval: (c-set-style "gnu")
* End:
*/
