#define _GNU_SOURCE
#include <pthread.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <dlfcn.h>
#include "load_libudpapp.h"

#define LIBFILE "/usr/lib64/libudpapp.so"

libudpapp_init_fn		libudpapp_init_fun = NULL;
libudpapp_uninit_fn		libudpapp_uninit_fun = NULL;
libudpapp_ingress_fn	libudpapp_ingress_fun = NULL;
libudpapp_set_egress_fun_fn libudpapp_set_egress_fun = NULL;
libudpapp_ioctl_fn		libudpapp_ioctl_fun = NULL;
void* handle = NULL;

int load_libudpapp(void)
{
	char* lib_name = getenv("LIBUDPAPP_FILE");
	if(!lib_name)
		lib_name = LIBFILE;
	
	handle = dlopen(lib_name, RTLD_LAZY);
	if (handle == NULL) {
		printf("[Error] dlopen(%s) failed, error: %s\n", lib_name, dlerror());
		return -1;
	}
	
	libudpapp_init_fun = dlsym(handle, "libudpapp_init");
	if (!libudpapp_init_fun) {
		printf("[Error] dlsym(libudapp_init) failed, error: %s\n", dlerror());
		return -1;
	}

	libudpapp_uninit_fun = dlsym(handle, "libudpapp_uninit");
	if (!libudpapp_uninit_fun) {
		printf("[Error] dlsym(libudpapp_uninit) failed, error: %s\n", dlerror());
		return -1;
	}

	libudpapp_ingress_fun = dlsym(handle, "libudpapp_ingress");
	if (!libudpapp_ingress_fun) {
		printf("[Error] dlsym(libudpapp_ingress) failed, error: %s\n", dlerror());
		return -1;
	}

	libudpapp_set_egress_fun = dlsym(handle, "libudpapp_set_egress");
	if (!libudpapp_set_egress_fun) {
		printf("[Error] dlsym(libudpapp_set_egress) failed, error: %s\n", dlerror());
		return -1;
	}

	libudpapp_ioctl_fun = dlsym(handle, "libudpapp_ioctl");
	if (!libudpapp_ioctl_fun) {
		printf("[Error] dlsym(libudpapp_ioctl) failed, error: %s\n", dlerror());
		return -1;
	}	
	return 0;
}


void unlod_libudpapp(void)
{
	printf("[Note][%s:%d] enter fun.\n", __func__, __LINE__);
	if (handle) {
		dlclose(handle);
		handle = NULL;
	}
	libudpapp_init_fun = NULL;
	libudpapp_uninit_fun = NULL;
	libudpapp_ingress_fun = NULL;
	libudpapp_set_egress_fun = NULL;
	libudpapp_ioctl_fun = NULL;
}

static int strsplit_with_delim(char *string, int stringlen,
		 char **tokens, int maxtokens, char delim)
{
	int i, tok = 0;
	int tokstart = 1; /* first token is right at start of string */

	if (string == NULL || tokens == NULL)
		goto einval_error;

	for (i = 0; i < stringlen; i++) {
		if (string[i] == '\0' || tok >= maxtokens)
			break;
		if (tokstart) {
			tokstart = 0;
			tokens[tok++] = &string[i];
		}
		if (string[i] == delim) {
			string[i] = '\0';
			tokstart = 1;
		}
	}
	return tok;

einval_error:
	errno = EINVAL;
	return -1;
}

static pthread_t libudpapp_tid;

static void* libudpapp_worker_task(void* arg)
{
	pthread_setname_np(pthread_self(), "libudpapp_work_task");
	
	int udpapp_argc = 1;
	int i  = 0;
	char full_cmdline[512] = {0};
	char* str = getenv("LIBUDPAPP_ARG");
	if (str) {
		strncpy(full_cmdline, str, strlen(str));
	}
	else {		
		printf("[Error] Please set enviroment:	LIBUPAPP_ARG befor run.\n");
		return NULL;
	}
	int cmdlen = strlen(full_cmdline);
	for (i = 0; i < cmdlen; ++i) {
		if (isspace(full_cmdline[i]))
			++udpapp_argc;
	}	
	char *udpapp_argv[udpapp_argc];

	udpapp_argc = strsplit_with_delim(full_cmdline, strlen(full_cmdline), 
		udpapp_argv, udpapp_argc, ' ');
	printf("argc:%d\n", udpapp_argc);
	for (i = 0; i < udpapp_argc; ++i)
		printf("arg[%d]: %s\n", i, udpapp_argv[i]);

	if (libudpapp_init_fun) 
		libudpapp_init_fun(udpapp_argc, udpapp_argv);
	return NULL;
}	

int libudpapp_init(void)
{
#if 1
	int ret = pthread_create(&libudpapp_tid, NULL, libudpapp_worker_task, NULL);
	if (ret < 0) {
		printf("[Error] pthread_create failed.\n");
		return -1;
	}
	int cpu = 3;
	cpu_set_t cpuset;
	CPU_ZERO(&cpuset);
	CPU_SET(cpu, &cpuset);
	ret = pthread_setaffinity_np(libudpapp_tid, sizeof(cpu_set_t), &cpuset);
	if (ret != 0) {
		printf("[Error] pthread_setaffinity_np failed.\n");
		return -1;
	}
	return 0;
#else
	int udpapp_argc = 1;
	char *udpapp_argv[udpapp_argc];
	udpapp_argv[0] = "udpapp";
	if (libudpapp_init_fun) 
		libudpapp_init_fun(udpapp_argc, udpapp_argv);
#endif
}

int libudpapp_uninit(void)
{
	if (libudpapp_uninit_fun) 
		return libudpapp_uninit_fun();
	return -1;
}

int libudpapp_ingress(unsigned char* buf, unsigned int data_len, dgram_hdr_t* dhdr)
{
	if (libudpapp_ingress_fun) 
		return libudpapp_ingress_fun(buf, data_len, dhdr);
	return -1;
}

int libudpapp_set_egress(egress_vpp_fn_t fn)
{
	if (libudpapp_set_egress_fun)
		return libudpapp_set_egress_fun(fn);
	return -1;
}

int libudpapp_ioctl(unsigned int cmd, void* arg)
{
	if (libudpapp_ioctl_fun)
		return libudpapp_ioctl_fun(cmd, arg);
	return -1;
}

