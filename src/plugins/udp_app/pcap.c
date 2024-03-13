#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <vnet/ethernet/ethernet.h>
#include "udpapp_fifo.h"

#define __clib_packed __attribute__ ((packed))
u8 ether_1[6] = {0x20,0x30,0x40,0x50,0x60,0x01};
u8 ether_2[6] = {0x20,0x30,0x40,0x50,0x60,0x02};

#define GTPU_LEN 16
typedef struct {
	u32 magic;
	u16 major;
	u16 minor;
	u32 timezone;
	u32 acc;
	u32 snaplen;
	u32 is_ethernet;
} __clib_packed pcap_head_t; 

typedef struct {
	u32 sec;
	u32 usec;
	u32 save_packet_len;
	u32 snaplen_packet_len;
}__clib_packed packet_head_t;

typedef struct {
	packet_head_t head;
	char data[0];
}__clib_packed one_packet_data_t;


typedef struct {
	char file_name[256];
	FILE* fd;
	int pcap_open;
	fifo_t dl_packet_fifo;
	fifo_t ul_packet_fifo;
	pthread_t write_thread_handle;
}pcap_file_info_t;


pcap_file_info_t pcap_i = {0};

#define PCAP_DIR "/root/"
#define PCAP_FILE "udpapp.pcap"
static void* write_packet_thread(void* arg);

static void create_write_thread_handle(int cpuid)
{
	int ret = pthread_create(&pcap_i.write_thread_handle, NULL, write_packet_thread, NULL);
	if (ret < 0) {
		printf("[Error] pthread_create failed.\n");
		return ;
	}
	int cpu = 15;
	if (cpuid != 0)
		cpu = cpuid;
	cpu_set_t cpuset;
	CPU_ZERO(&cpuset);
	CPU_SET(cpu, &cpuset);
	ret = pthread_setaffinity_np(pcap_i.write_thread_handle, sizeof(cpu_set_t), &cpuset);
	if (ret != 0) {
		printf("[Error] pthread_setaffinity_np failed.\n");
		return ;
	}
}

const char* open_close_udpapp_pcap(const char *pathname, u8 is_open, int cpuid)
{
	if (is_open == 1) {

		if (pathname == NULL)
			snprintf(pcap_i.file_name, sizeof(pcap_i.file_name) - 1, "%s%s", PCAP_DIR, PCAP_FILE);
		else if (pathname[0] == '/')
			strcpy(pcap_i.file_name, pathname);
		else
			snprintf(pcap_i.file_name, sizeof(pcap_i.file_name) - 1, "%s%s", PCAP_DIR, pathname);

		pcap_i.fd = fopen(pcap_i.file_name, "w");
		if (pcap_i.fd == NULL) {
			printf("[Error] open file: %s failed.\n", pcap_i.file_name);
			return NULL;
		}
		printf("[Note] pcap file: %s\n", pcap_i.file_name);
		pcap_head_t head = {0};
		head.magic = 0xa1b2c3d4;
		head.major = 2;
		head.minor = 4;
		head.timezone = 0;
		head.acc = 0;
		head.snaplen = 0xffff;
		head.is_ethernet = 1;
		fwrite((u8*)&head, 1, sizeof(pcap_head_t), pcap_i.fd);
		fflush(pcap_i.fd);
		fifo_init(&pcap_i.dl_packet_fifo, 1 << 20);
		fifo_init(&pcap_i.ul_packet_fifo, 1 << 20);
		
		pcap_i.pcap_open = 1;
		create_write_thread_handle(cpuid);
		
	}
	else {
		if (pcap_i.pcap_open == 1) {
			fclose(pcap_i.fd);
			pcap_i.fd = NULL;
			fifo_uninit(&pcap_i.ul_packet_fifo);
			fifo_uninit(&pcap_i.dl_packet_fifo);
		}
		pcap_i.pcap_open = 0;
	}
	return pcap_i.file_name;
}

void write_pcap(one_packet_data_t* pkt, u32 total_len)
{
	if (pcap_i.pcap_open != 1)
		return ;
	fwrite((u8*)pkt, 1, total_len, pcap_i.fd);
	fflush(pcap_i.fd);
}

static void* write_packet_thread(void* arg)
{
	int dl_count = 0;
	int ul_count = 0;
	int count = 0;
	int i = 0;
	void** data_node_arr = NULL;
	one_packet_data_t *pkt = NULL;
	pthread_setname_np(pthread_self(), "udpapp_pcap");
	while(pcap_i.pcap_open == 1) {
		dl_count = fifo_count(&pcap_i.dl_packet_fifo);
		if (dl_count > 0) {
			vec_validate(data_node_arr, dl_count - 1);
			count = fifo_get(&pcap_i.dl_packet_fifo, data_node_arr, dl_count);
			for(i = 0; i < count; i++) {
				pkt = (one_packet_data_t*)data_node_arr[i];
				write_pcap(pkt, sizeof(packet_head_t) + pkt->head.snaplen_packet_len);
				free(pkt);
			}
			vec_free(data_node_arr);
		}
		ul_count = fifo_count(&pcap_i.ul_packet_fifo);
		if (ul_count > 0) {
			vec_validate(data_node_arr, ul_count - 1);
			count = fifo_get(&pcap_i.ul_packet_fifo, data_node_arr, ul_count);
			for(i = 0; i < count; i++) {
				pkt = (one_packet_data_t*)data_node_arr[i];
				write_pcap(pkt, sizeof(packet_head_t) + pkt->head.snaplen_packet_len);
				free(pkt);
			}
			vec_free(data_node_arr);
		}
	}
	return NULL;
}

void udpapp_ingress_pcap(u8* data, u32 len, u8 is_ip4)
{
	one_packet_data_t *pkt = NULL;
	struct timeval t;
	ethernet_header_t* eth = NULL;
	u32 packet_len = len - (GTPU_LEN - sizeof(ethernet_header_t));
	if (pcap_i.pcap_open == 1 && len != 0 && data) {				
		pkt = malloc(sizeof(one_packet_data_t) + packet_len);
		if (pkt == NULL) {
			printf("[Error][%s:%d] malloc failed.\n", __func__, __LINE__);
			return ;
		}
		gettimeofday(&t, NULL);
		pkt->head.sec = t.tv_sec;
		pkt->head.usec = t.tv_usec;
		pkt->head.save_packet_len = packet_len;
		pkt->head.snaplen_packet_len = packet_len;
		eth = (ethernet_header_t*)pkt->data;
		if (is_ip4)
			eth->type = htons(ETHERNET_TYPE_IP4);
		else
			eth->type = htons (ETHERNET_TYPE_IP6);
		clib_memcpy(eth->dst_address, ether_1, sizeof(ether_1));
		clib_memcpy(eth->src_address, ether_2, sizeof(ether_2));
		clib_memcpy(pkt->data + sizeof(ethernet_header_t), data + GTPU_LEN, len - GTPU_LEN);

		if (fifo_put(&pcap_i.dl_packet_fifo, (void**)&pkt, 1) != 1) {
			printf("[Error] [%s:%d] fifo_put failed!\n", __func__, __LINE__);
			free(pkt);
			return ;
		}
	}
}

void udpapp_egress_pcap(u8* data, u32 len, u8 is_ip4)
{
	one_packet_data_t *pkt = NULL;
	struct timeval t;
	ethernet_header_t* eth = NULL;
	u32 packet_len = len - (GTPU_LEN - sizeof(ethernet_header_t));
	if (pcap_i.pcap_open == 1 && len != 0 && data) {				
		pkt = malloc(sizeof(one_packet_data_t) + packet_len);
		if (pkt == NULL) {
			printf("[Error][%s:%d] malloc failed.\n", __func__, __LINE__);
			return ;
		}
		gettimeofday(&t, NULL);
		pkt->head.sec = t.tv_sec;
		pkt->head.usec = t.tv_usec;
		pkt->head.save_packet_len = packet_len;
		pkt->head.snaplen_packet_len = packet_len;
		eth = (ethernet_header_t*)(pkt->data);
		if (is_ip4)
			eth->type = htons(ETHERNET_TYPE_IP4);
		else
			eth->type = htons (ETHERNET_TYPE_IP6);
		clib_memcpy(eth->dst_address, ether_2, sizeof(ether_2));
		clib_memcpy(eth->src_address, ether_1, sizeof(ether_1));
		clib_memcpy(pkt->data + sizeof(ethernet_header_t), data + GTPU_LEN, len - GTPU_LEN);

		if (fifo_put(&pcap_i.ul_packet_fifo, (void**)&pkt, 1) != 1) {
			printf("[Error] [%s:%d] fifo_put failed!\n", __func__, __LINE__);
			free(pkt);
			return ;
		}
	}
}

