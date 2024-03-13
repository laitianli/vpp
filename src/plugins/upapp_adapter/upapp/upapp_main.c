#define _GNU_SOURCE
#include <pthread.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include "upapp_fifo.h"
#include "dgram_hdr.h"

unsigned char debug_on = 0;

#define MY_Debug(fmt, args...) do { \
    if (debug_on == 1) \
        printf("[Note][%s:%d]"fmt"\n", __func__, __LINE__, ##args); \
}while(0)

typedef int (*ul_vpp_fn_t)(unsigned char* data, unsigned int len, dgram_hdr_t* dhdr);

ul_vpp_fn_t ul_fn = NULL;
struct upapp_fifo mbuf_fifo;
struct upapp_fifo mbuf_fifo_for_tx;

static pthread_t upapp_tid;
static u8 exit_flag = 0;

#define MBUF_FIFO_SIZE  2048

#define LIBUPAPP_IOCTL_CMD_DEBUG 	0x001
#define LIBUPAPP_IOCTL_CMD_OPEN_SNED 0x002
unsigned char send_thread_isalive = 0;

typedef void (*data_node_destructor_t)(void* dn);
struct data_node {
	data_node_destructor_t data_node_destructor_fn;
	int data_len;
    void*          pmbuf;
	unsigned char *data;
	dgram_hdr_t		hdr;
};
typedef struct _client_packet_info {
	int count;
	int length;
	dgram_hdr_t hdr;
}client_packet_info_t;


static client_packet_info_t cpi = {0};

#define DATA_BUF_SIZE 2048
static char data_buf[DATA_BUF_SIZE + 1] = {0};

#define DATA_NODE_SIZE(data_len) (sizeof(struct data_node) + data_len)
static void libupapp_data_node_destruction(void* dn);

void exchange_ip_port(dgram_hdr_t* dhdr)
{
#if 0
	u16 port = 0;
	ip46_address_t ip46 = {0};
	port = dhdr->rmt_port;
	dhdr->rmt_port = dhdr->lcl_port;
	dhdr->lcl_port = port;
	memcpy(&ip46, &dhdr->lcl_ip, sizeof(ip46_address_t));
	memcpy(&dhdr->lcl_ip, &dhdr->rmt_ip, sizeof(ip46_address_t));
	memcpy(&dhdr->rmt_ip, &ip46, sizeof(ip46_address_t));
#else
	dhdr->rmt_port = htons(2153);
#endif	
}

static void* upapp_worker_task(void* arg)
{
#define MAX_FIFO_COUNT 128
	struct data_node* arr_dn[MAX_FIFO_COUNT] = {NULL};
	struct data_node* dn = NULL;
	unsigned int count = 0, cur_count = 0;
	unsigned int count_rx = 0, cur_count_rx = 0;
	int i = 0;
	pthread_setname_np(pthread_self(), "upapp_work_task");
	while (1) {
		count = upapp_fifo_count(&mbuf_fifo);
		count_rx = upapp_fifo_count(&mbuf_fifo_for_tx);
		if (count == 0 && count_rx == 0) {
			//usleep(600);
			if (exit_flag == 1)
                break;
			continue;
		}
		if (count) {
			cur_count = count > MAX_FIFO_COUNT ? MAX_FIFO_COUNT : count;
			upapp_fifo_get(&mbuf_fifo, (void**)arr_dn, cur_count);
			for (i = 0; i < cur_count; i++) {
				dn = arr_dn[i];
				MY_Debug("len: %d, data: %s", dn->data_len, dn->data);
				if(ul_fn) {
					exchange_ip_port(&dn->hdr);
					ul_fn((unsigned char*)dn, sizeof(struct data_node*), &dn->hdr);
				}
			}
		}
		if (count_rx) {
			cur_count_rx = count_rx > MAX_FIFO_COUNT ? MAX_FIFO_COUNT : count_rx;
			upapp_fifo_get(&mbuf_fifo_for_tx, (void**)arr_dn, cur_count_rx);
			for (i = 0; i < cur_count_rx; i++) {
				dn = arr_dn[i];
				MY_Debug("len: %d, data: %s", dn->data_len, dn->data);
				if(ul_fn) {
					exchange_ip_port(&dn->hdr);
					ul_fn((unsigned char*)dn, sizeof(struct data_node*), &dn->hdr);
				}
			}
		}
	}
	return 0;
}

int sys_timer_system_init(void);

int libupapp_main_init(int argc, char**argv)
{
	MY_Debug("enter function.");
	upapp_fifo_init(&mbuf_fifo, 256 << 10);
	upapp_fifo_init(&mbuf_fifo_for_tx, 256 << 10);
	upapp_worker_task(NULL);
    //sys_timer_system_init();
	return 0;
}

int libupapp_main_uninit(void)
{
	MY_Debug("enter function.");
    
    exit_flag = 1;
    pthread_join(upapp_tid, NULL);
    int i = 0;
    struct data_node* dn = NULL;
    int count = upapp_fifo_count(&mbuf_fifo);
    for (i = 0; i < count; i++) {        
        upapp_fifo_get(&mbuf_fifo, (void**)&dn, 1);
        if (dn->data_node_destructor_fn)
            dn->data_node_destructor_fn(dn);
    }
    upapp_fifo_uninit(&mbuf_fifo);
	return 0;
}

static void libupapp_data_node_destruction(void* dn)
{
	if (dn) {	
        struct data_node* p = (struct data_node*)dn;
        if (p->pmbuf) {
            free(p->pmbuf);
        }		
		free(dn);
    }
}

struct data_node* get_data_node(int data_len)
{
	struct data_node* dn = malloc(sizeof(struct data_node));
	if(!dn) {
		printf("[Error] malloc data node failed!\n");
		return NULL;
	}
	dn->data = malloc(data_len);
    if (!dn->data) {
        printf("[Error] [%s:%d]malloc data failed!\n", __func__, __LINE__);
        free(dn);
		return NULL;
    }

	return dn;
}


int libupapp_dl(unsigned char* buf, unsigned int data_len, dgram_hdr_t* dhdr)
{
	MY_Debug("enter function. data_len: %d,buf:%s", data_len, buf);
	struct data_node* dn = get_data_node(data_len);
	if(!dn) {
		printf("[Error] malloc data node failed!\n");
		return -1;
	}
	DUMP_HDR(dhdr);
	MY_Debug("ptheadid: %x, dn: %p, data: %p", (u32)pthread_self(), dn, dn->data);
    dn->pmbuf = dn->data;
	dn->data_len = data_len;
	memcpy(dn->data, buf, data_len);
	memcpy(&dn->hdr, dhdr, sizeof(dgram_hdr_t));
	dn->data_node_destructor_fn = libupapp_data_node_destruction;
	if (upapp_fifo_put(&mbuf_fifo, (void**)&dn, 1) != 1) {
		dn->data_node_destructor_fn(dn);
		return -1;
	}
	return data_len;
}

int libupapp_dl_for_tx(unsigned char* buf, unsigned int data_len, dgram_hdr_t* dhdr)
{
	MY_Debug("enter function. data_len: %d,buf:%s", data_len, buf);
	struct data_node* dn = get_data_node(data_len);
	if(!dn) {
		printf("[Error] malloc data node failed!\n");
		return -1;
	}
	DUMP_HDR(dhdr);
	MY_Debug("ptheadid: %x, dn: %p, data: %p", (u32)pthread_self(), dn, dn->data);
    dn->pmbuf = dn->data;
	dn->data_len = data_len;
	memcpy(dn->data, buf, data_len);
	memcpy(&dn->hdr, dhdr, sizeof(dgram_hdr_t));
	dn->data_node_destructor_fn = libupapp_data_node_destruction;
	if (upapp_fifo_put(&mbuf_fifo_for_tx, (void**)&dn, 1) != 1) {
		dn->data_node_destructor_fn(dn);
		return -1;
	}
	return data_len;
}


int libupapp_set_ul_send_fun(ul_vpp_fn_t fn)
{
	MY_Debug("enter function. fn: 0x%p", fn);
	ul_fn = fn;
	return 0;
}


static void _do_libupapp_send_test_packet(void* arg)
{
	client_packet_info_t* pcinfo = (client_packet_info_t*)arg;
	exchange_ip_port(&pcinfo->hdr);
	MY_Debug("count:%d, length: %d\n", pcinfo->count, pcinfo->length);
	int i = 0;
	int len = (pcinfo->length > DATA_BUF_SIZE) ? DATA_BUF_SIZE : pcinfo->length;
	send_thread_isalive = 1;
	for (i = 0; i < len; i++) {
		data_buf[i] = 'a' + i % 26;
	}
	data_buf[len - 1] = '\n';
#if 0		
	dgram_hdr_t hdr = {0};
	hdr.is_ip4 = 1;
	hdr.lcl_ip.ip4.as_u32 = 0x6060606 ;
	hdr.lcl_port = htons(43084);
	hdr.rmt_ip.ip4.as_u32 = 0xfb060606;
	hdr.rmt_port = htons(2153);
#endif
	char index_buf[20] = {0};
	int count = 0;
	for (i = 0; i < pcinfo->count; i++) {
		snprintf(index_buf, sizeof(index_buf), "[%016d]", i);
		memcpy(data_buf, index_buf, 18);
		libupapp_dl_for_tx(data_buf, len, &pcinfo->hdr);
		if (count++ >= 10) {
			usleep(1);
			count = 0;
		}
	}
	send_thread_isalive = 0;
}


static void* client_send_worker_task(void* arg)
{
	pthread_setname_np(pthread_self(), "clt_send");
	_do_libupapp_send_test_packet(arg);
}


int libupapp_ioctl(unsigned int cmd, void* arg)
{
	MY_Debug("enter function.");
	switch (cmd) {
		case LIBUPAPP_IOCTL_CMD_DEBUG:
		{
			debug_on = *(int*)arg;
			break;
		}
		case LIBUPAPP_IOCTL_CMD_OPEN_SNED:
		{
			pthread_t c_tid;
			if (send_thread_isalive == 1) {
				printf("[Warning][%s:%d] send thread is alive, so exit curr cmd!\n", __func__, __LINE__);
				return 0;
			}
			memcpy(&cpi, arg, sizeof(client_packet_info_t));
			int ret = pthread_create(&c_tid, NULL, client_send_worker_task, (void*)&cpi);
			if (ret < 0) {
				printf("[Error] pthread_create failed.\n");
				return -1;
			}
			int cpu = 6;
			cpu_set_t cpuset;
			CPU_ZERO(&cpuset);
			CPU_SET(cpu, &cpuset);
			ret = pthread_setaffinity_np(c_tid, sizeof(cpu_set_t), &cpuset);
			if (ret != 0) {
				printf("[Error] pthread_setaffinity_np failed.\n");
				return -1;
			}
			break;
		}
		default:
			break;
	}
	return 0;
}


