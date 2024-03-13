#ifndef __COMMON_H__
#define __COMMON_H__

#include "upapp.h"
extern unsigned char debug_on;

#define MY_Debug(fmt, args...) do { \
    if (debug_on == 1) \
        printf("[Note][%s:%d]"fmt"\n", __func__, __LINE__, ##args); \
}while(0)


#define DUMP_HDR(dhdr) do { \
	if (debug_on == 1) {\
	    if (dhdr->is_ip4) { \
			u32 r = dhdr->rmt_ip.ip4.as_u32; \
			u32 l = dhdr->lcl_ip.ip4.as_u32; \
	        printf("[%s:%d] lib ipv4: rmt: %d.%d.%d.%d (%u), lcl_ip: %d.%d.%d.%d (%u)\n", __func__, __LINE__, \
	             (r & 0xFF), ((r >> 8) & 0xFF), ((r >> 16) & 0xFF), ((r >> 24) & 0xFF), ntohs(dhdr->rmt_port),    \
	             (l & 0xFF), ((l >> 8) & 0xFF), ((l >> 16) & 0xFF), ((l >> 24) & 0xFF), ntohs(dhdr->lcl_port));   \
	    }   \
	    else {  \
	        printf("ipv6: \n"); \
	    }   \
	}	\
} while(0)

#define DUMP_HDR_OPEN(dhdr) do { \
	    if (dhdr->is_ip4) { \
			u32 r = dhdr->rmt_ip.ip4.as_u32; \
			u32 l = dhdr->lcl_ip.ip4.as_u32; \
	        printf("[%s:%d] lib ipv4: rmt: %d.%d.%d.%d (%u), lcl_ip: %d.%d.%d.%d (%u)\n", __func__, __LINE__, \
	             (r & 0xFF), ((r >> 8) & 0xFF), ((r >> 16) & 0xFF), ((r >> 24) & 0xFF), ntohs(dhdr->rmt_port),    \
	             (l & 0xFF), ((l >> 8) & 0xFF), ((l >> 16) & 0xFF), ((l >> 24) & 0xFF), ntohs(dhdr->lcl_port));   \
	    }   \
	    else {  \
	        printf("ipv6: \n"); \
	    }   \
} while(0)

struct gtpu_stat {
	u64 ipackets;
	u64 ibytes;
	u64 ipackets_succ;
	u64 ibytes_succ;
	u64 opackets;
	u64 obytes;
	u64 opackets_succ;
	u64 obytes_succ;
	u64 ierrors;
	u64 oerrors;
	u64 oerrors_full;
};

typedef void (*data_node_destructor_t)(void* dn);
struct data_node_head {
	data_node_destructor_t data_node_destructor_fn;
	int data_len;
    void*          pmbuf;
	unsigned char *data;
	dgram_hdr_t    dhdr;	
};

typedef struct svm_fifo_dgram_hdr_seg {
    session_dgram_hdr_t shdr;
    svm_fifo_seg_t seg;
}svm_fifo_dgram_hdr_seg_t;


//void gtpu_client_init(vlib_main_t* vm);

//void gtpu_client_uninit(vlib_main_t* vm);

typedef struct
{
	/*
	* Application setup parameters
	*/
	svm_msg_q_t **vpp_event_queue;

	u32 app_index;			/**< app index after attach */
	/*
	* Configuration params
	*/
	session_endpoint_cfg_t connect_sep;	/**< Sever session endpoint */
	u32 fifo_size;
	u32 private_segment_count;		/**< Number of private fifo segs */
	u64 private_segment_size;		/**< size of private fifo segs */
	
	u8 *appns_id;				/**< App namespaces id */
	
	/*
	* Flags
	*/
	u8 gtpu_client_attached;
	session_t** connect_session;
	transport_connection_t ** cs_tc;
	struct gtpu_stat stat;
	vlib_main_t *vlib_main;
} gtpu_client_main_t;


int gtpu_clients_attach(void);

session_t * get_client_session_ext(dgram_hdr_t *dhdr);

#endif



