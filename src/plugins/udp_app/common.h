#ifndef __COMMON_H__
#define __COMMON_H__
#include <vnet/vnet.h>
typedef struct _dgram_header_ {
	ip46_address_t	rmt_ip;
	ip46_address_t	lcl_ip;
	u16				rmt_port;
	u16				lcl_port;
	u8				is_ip4;
} __clib_packed dgram_hdr_t;

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
				 (r & 0xFF), ((r >> 8) & 0xFF), ((r >> 16) & 0xFF), ((r >> 24) & 0xFF), ntohs(dhdr->rmt_port),	  \
				 (l & 0xFF), ((l >> 8) & 0xFF), ((l >> 16) & 0xFF), ((l >> 24) & 0xFF), ntohs(dhdr->lcl_port));	  \
		}	\
		else {	\
			printf("ipv6: \n"); \
		}	\
	}	\
} while(0)

#define DUMP_HDR_OPEN(dhdr) do { \
		if (dhdr->is_ip4) { \
			u32 r = dhdr->rmt_ip.ip4.as_u32; \
			u32 l = dhdr->lcl_ip.ip4.as_u32; \
			printf("[%s:%d] lib ipv4: rmt: %d.%d.%d.%d (%u), lcl_ip: %d.%d.%d.%d (%u)\n", __func__, __LINE__, \
				 (r & 0xFF), ((r >> 8) & 0xFF), ((r >> 16) & 0xFF), ((r >> 24) & 0xFF), ntohs(dhdr->rmt_port),	  \
				 (l & 0xFF), ((l >> 8) & 0xFF), ((l >> 16) & 0xFF), ((l >> 24) & 0xFF), ntohs(dhdr->lcl_port));	  \
		}	\
		else {	\
			printf("ipv6: \n"); \
		}	\
} while(0)

typedef struct {
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
}udp_fwd_stat_t;

typedef void (*data_node_destructor_t)(void* dn);
struct data_node_head {
	data_node_destructor_t data_node_destructor_fn;
	int data_len;
	void*		   pmbuf;
	unsigned char *data;
	dgram_hdr_t	   dhdr;	
};

typedef struct
{
	u16				udp_port;
	udp_fwd_stat_t	stat;
	u8				create_flag;
	u8				pcap_flag;
}udpapp_main_t;

extern udpapp_main_t udpapp_main;

extern int udpapp_egress_xmit(u8* buf, u32 data_len, dgram_hdr_t *dhdr);
extern int udpapp_egress_init(vlib_main_t* vm);
extern void udpapp_egress_uninit(vlib_main_t* vm);

extern const char* open_close_udpapp_pcap(const char *pathname, u8 is_open, int cpuid);
extern void udpapp_egress_pcap(u8* data, u32 len, u8 is_ip4);
extern void udpapp_ingress_pcap(u8* data, u32 len, u8 is_ip4);

#endif

