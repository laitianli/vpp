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
#include "upapp.h"

#define LIBFILE "/home/haizhi/downland/vpp/src/plugins/upapp_adapter/upapp/libupapp.so"

libupapp_main_init_fn libupapp_main_init_fun;
libupapp_main_uninit_fn libupapp_main_uninit_fun;
libupapp_dl_fn libupapp_dl_fun;
libupapp_set_ul_send_fun_fn libupapp_set_ul_send_fun;
libupapp_ioctl_fn libupapp_ioctl_fun;
void* lib_handle = NULL;

int load_libupapp(void)
{
	char* lib_name = getenv("LIBUPAPP_PATH");
	if(!lib_name)
		lib_name = LIBFILE;
	
	lib_handle = dlopen(lib_name, RTLD_LAZY);
	if (lib_handle == NULL) {
		printf("[Error] dlopen(%s) failed, error: %s\n", lib_name, dlerror());
		return -1;
	}
	
	libupapp_main_init_fun = dlsym(lib_handle, "libupapp_main_init");
	if (!libupapp_main_init_fun) {
		printf("[Error] dlsym(libupapp_main_init) failed, error: %s\n", dlerror());
		return -1;
	}

	libupapp_main_uninit_fun = dlsym(lib_handle, "libupapp_main_uninit");
	if (!libupapp_main_uninit_fun) {
		printf("[Error] dlsym(libupapp_main_uninit) failed, error: %s\n", dlerror());
		return -1;
	}

	libupapp_dl_fun = dlsym(lib_handle, "libupapp_dl");
	if (!libupapp_dl_fun) {
		printf("[Error] dlsym(libupapp_dl) failed, error: %s\n", dlerror());
		return -1;
	}

	libupapp_set_ul_send_fun = dlsym(lib_handle, "libupapp_set_ul_send_fun");
	if (!libupapp_set_ul_send_fun) {
		printf("[Error] dlsym(libupapp_set_ul_send_fun) failed, error: %s\n", dlerror());
		return -1;
	}

	libupapp_ioctl_fun = dlsym(lib_handle, "libupapp_ioctl");
	if (!libupapp_ioctl_fun) {
		printf("[Error] dlsym(libupapp_ioctl) failed, error: %s\n", dlerror());
		return -1;
	}   
	return 0;
}


void unlod_libupapp(void)
{
    printf("[Note][%s:%d] enter fun.\n", __func__, __LINE__);
	if (lib_handle) {
		dlclose(lib_handle);
		lib_handle = NULL;
	}
	libupapp_main_init_fun = NULL;
	libupapp_main_uninit_fun = NULL;
	libupapp_dl_fun = NULL;
	libupapp_set_ul_send_fun = NULL;
	libupapp_ioctl_fun = NULL;
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

static pthread_t libupapp_tid;

static void* libupapp_worker_task(void* arg)
{
    pthread_setname_np(pthread_self(), "libupapp_work_task");
    
	int upapp_argc = 1;
	int i  = 0;
	char full_cmdline[512] = {0};
	char* str = getenv("LIBUPAPP_ARG");
	if (str) {
		strncpy(full_cmdline, str, strlen(str));
	}
	else {		
		printf("[Error] Please set enviroment:  LIBUPAPP_ARG befor run.\n");
		return NULL;
	}
	int cmdlen = strlen(full_cmdline);
	for (i = 0; i < cmdlen; ++i) {
		if (isspace(full_cmdline[i]))
			++upapp_argc;
	}	
	char *upapp_argv[upapp_argc];

	upapp_argc = strsplit_with_delim(full_cmdline, strlen(full_cmdline), 
        upapp_argv, upapp_argc, ' ');
	printf("argc:%d\n", upapp_argc);
	for (i = 0; i < upapp_argc; ++i)
		printf("arg[%d]: %s\n", i, upapp_argv[i]);

	if (libupapp_main_init_fun) 
		libupapp_main_init_fun(upapp_argc, upapp_argv);
    //printf("[Note][%s:%d] thread: libupapp_worker_task exit\n", __func__, __LINE__);
    return NULL;
}   


int libuapp_init(void)
{
#if 1
	int ret = pthread_create(&libupapp_tid, NULL, libupapp_worker_task, NULL);
	if (ret < 0) {
		printf("[Error] pthread_create failed.\n");
		return -1;
	}
	int cpu = 17;
	cpu_set_t cpuset;
	CPU_ZERO(&cpuset);
	CPU_SET(cpu, &cpuset);
	ret = pthread_setaffinity_np(libupapp_tid, sizeof(cpu_set_t), &cpuset);
	if (ret != 0) {
		printf("[Error] pthread_setaffinity_np failed.\n");
		return -1;
	}
	return 0;
#else
    libupapp_worker_task(NULL);
    return 0;
#endif
}

int libuapp_uninit(void)
{
	if (libupapp_main_uninit_fun) 
		return libupapp_main_uninit_fun();
	return -1;
}

int libupapp_dl(unsigned char* buf, unsigned int data_len, dgram_hdr_t* dhdr)
{
	if (libupapp_dl_fun) 
		return libupapp_dl_fun(buf, data_len, dhdr);
	return -1;
}

int libupapp_set_ul_fun(ul_vpp_fn_t fn)
{
	if (libupapp_set_ul_send_fun)
		return libupapp_set_ul_send_fun(fn);
	return -1;
}

int libupapp_ioctl(unsigned int cmd, void* arg)
{
	if (libupapp_ioctl_fun)
		return libupapp_ioctl_fun(cmd, arg);
	return -1;
}

