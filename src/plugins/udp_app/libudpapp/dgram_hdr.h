#ifndef __DGRAM_HDR_H_
#define __DGRAM_HDR_H_
#include <arpa/inet.h>

#define __clib_packed __attribute__ ((packed))
#define CLIB_PACKED(x)	x __attribute__ ((packed))

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef u64 uword;

typedef union
{
  u8 data[4];
  u32 data_u32;
  /* Aliases. */
  u8 as_u8[4];
  u16 as_u16[2];
  u32 as_u32;
} ip4_address_t;

typedef union
{
  u8 as_u8[16];
  u16 as_u16[8];
  u32 as_u32[4];
  u64 as_u64[2];
  uword as_uword[16 / sizeof (uword)];
}__clib_packed ip6_address_t;

typedef CLIB_PACKED (union ip46_address_t_ {
  struct {
    u32 pad[3];
    ip4_address_t ip4;
  };
  ip6_address_t ip6;
  u8 as_u8[16];
  u64 as_u64[2];
}) ip46_address_t;

typedef struct _dgram_header_ {
	ip46_address_t	rmt_ip;
	ip46_address_t	lcl_ip;
	u16 			rmt_port;
	u16 			lcl_port;
	u8				is_ip4;
} __clib_packed dgram_hdr_t;
extern unsigned char debug_on;
#define DUMP_HDR(dhdr) do { \
		if (debug_on == 1) {\
			if (dhdr->is_ip4) { \
				u32 r = dhdr->rmt_ip.ip4.as_u32; \
				u32 l = dhdr->lcl_ip.ip4.as_u32; \
				printf("[%s:%d] lib ipv4: rmt: %d.%d.%d.%d (%u), lcl_ip: %d.%d.%d.%d (%u)\n", __func__, __LINE__, \
					 (r & 0xFF), ((r >> 8) & 0xFF), ((r >> 16) & 0xFF), ((r >> 24) & 0xFF), ntohs(dhdr->rmt_port),	  \
					 (l & 0xFF), ((l >> 8) & 0xFF), ((l >> 16) & 0xFF), ((l >> 24) & 0xFF), ntohs(dhdr->lcl_port));   \
			}	\
			else {	\
				printf("ipv6: \n"); \
			}	\
		}	\
	} while(0)


#endif

