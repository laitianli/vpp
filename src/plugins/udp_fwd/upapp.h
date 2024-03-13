#ifndef __UPAPP_H_
#define __UPAPP_H_
#include <vnet/vnet.h>
#include <vnet/session/session.h>
#include "common.h"

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


