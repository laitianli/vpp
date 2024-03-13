#ifndef __LOAD_LIBUDPAPP_H_
#define __LOAD_LIBUDPAPP_H_
#include <vnet/vnet.h>
#include <vnet/session/session.h>
#include "common.h"

typedef int(*egress_vpp_fn_t) (unsigned char * data, unsigned int len, dgram_hdr_t * dhdr);
typedef int(*libudpapp_init_fn) (int argc, char * *argv);
typedef int(*libudpapp_uninit_fn) (void);
typedef int(*libudpapp_ingress_fn) (unsigned char * buf, unsigned int data_len, dgram_hdr_t * dhdr);
typedef int(*libudpapp_set_egress_fun_fn) (egress_vpp_fn_t fn);
typedef int(*libudpapp_ioctl_fn) (unsigned int cmd, void * arg);

int load_libudpapp(void);

void unlod_libudpapp(void);

int libudpapp_init(void);

int libudpapp_uninit(void);

int libudpapp_ingress(unsigned char * buf, unsigned int data_len, dgram_hdr_t * dhdr);

int libudpapp_set_egress(egress_vpp_fn_t fn);

int libudpapp_ioctl(unsigned int cmd, void * arg);

#endif


