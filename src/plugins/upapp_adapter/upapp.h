#ifndef __UPAPP_H_
#define __UPAPP_H_
#include <vnet/vnet.h>
#include <vnet/session/session.h>

#if 0
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;


typedef union {
	u8				data[4];
	u32 			data_u32;

	/* Aliases. */
	u8				as_u8[4];
	u16 			as_u16[2];
	u32 			as_u32;
} ip4_address_t;

typedef union
{
    u8 as_u8[16];
    u16 as_u16[8];
    u32 as_u32[4];
    u64 as_u64[2];
    u64x2 as_u128;
    uword as_uword[16 / sizeof (uword)];
}__attribute__ ((packed)) ip6_address_t;


typedef union ip46_address_t_ {
    struct {
        u32 pad[3];
        ip4_address_t ip4;
    };
    ip6_address_t ip6;
    u8 as_u8[16];
    u64 as_u64[2];
}__attribute__ ((packed)) ip46_address_t;
#endif


typedef struct _dgram_header_ {
	ip46_address_t	rmt_ip;
	ip46_address_t	lcl_ip;
	u16 			rmt_port;
	u16 			lcl_port;
	u8				is_ip4;
} __clib_packed dgram_hdr_t;


typedef int(*ul_vpp_fn_t) (unsigned char * data, unsigned int len, dgram_hdr_t * dhdr);
typedef int(*libupapp_main_init_fn) (int argc, char * *argv);
typedef int(*libupapp_main_uninit_fn) (void);
typedef int(*libupapp_dl_fn) (unsigned char * buf, unsigned int data_len, dgram_hdr_t * dhdr);
typedef int(*libupapp_set_ul_send_fun_fn) (ul_vpp_fn_t fn);
typedef int(*libupapp_ioctl_fn) (unsigned int cmd, void * arg);

int load_libupapp(void);

void unlod_libupapp(void);

int libuapp_init(void);

int libuapp_uninit(void);

int libupapp_dl(unsigned char * buf, unsigned int data_len, dgram_hdr_t * dhdr);

int libupapp_set_ul_fun(ul_vpp_fn_t fn);

int libupapp_ioctl(unsigned int cmd, void * arg);

#endif


