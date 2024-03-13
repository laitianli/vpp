/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <vnet/udp/udp.h>
#include "common.h"
#include "upapp.h"

unsigned char debug_on = 1;
udp_fwd_main_t udp_fwd_main = {0};

clib_error_t * udp46_fwd_register_gtpu_port(vlib_main_t * vm);
clib_error_t * udp46_fwd_unregister_gtpu_port(vlib_main_t * vm);

static int init_upapp(void)
{
	load_libupapp();
	libuapp_init();
	libupapp_set_ul_fun(udp_fwd_ul_xmit);
	return 0;
}

static void uninit_upapp(void)
{
	libuapp_uninit();
	unlod_libupapp();
}
/* udp_fwd启用 */
static void udp46_fwd_enable(vlib_main_t * vm)
{
	udp_fwd_main_t *ufm = &udp_fwd_main;
	/* 若udp_fwd已经启用，直接返回。
	 * 防止udp_fwd enable命令多次执行后导致libupapp.so重复加载
	 */
	if (ufm->create_flag == 1) 
		return ;
	/* 加载libupapp.so库 */
	init_upapp();
	
	/* 将gtpu端口加入到ipv4/6的端口列表中，
	 * 这样在ip层接收到对应端口的报文，就会转到此udp_fwd node
	 */
	udp46_fwd_register_gtpu_port(vm); 
	
	/* 针对上行方向的初始化 */
	udp_fwd_ul_init(vm);
	
	/* 标识udp_fwd已经创建完成 */
	ufm->create_flag = 1;
	return ;
}

/* udp_fwd禁用 */
static void udp46_fwd_disable(vlib_main_t * vm)
{	
	/* 将gtpu端口2152从ipv4/6端口列表中删除 */
	udp46_fwd_unregister_gtpu_port(vm);
	
	/* 卸载libupapp.so库 */
	uninit_upapp();
	
	/* 将UL使用的udp_fwd_ul_node节点状态从POLLING切换到DISABLED */
	udp_fwd_ul_uninit(vm);
	
	/* 将udp_fwd全局变量置0，防止使用命令再次加载libupapp.so库时状态错误 */
	memset(&udp_fwd_main, 0, sizeof(udp_fwd_main));
}

static void
udp_fwd_show_command_fn (vlib_main_t * vm)
{
	udp_fwd_main_t *ufm = &udp_fwd_main;
	vlib_cli_output (vm, "ipacket: %-16Lu ipacket_succ: %-16Lu ibytes: %-16Lu ibytes_succ: %-16Lu", 
			ufm->stat.ipackets, ufm->stat.ipackets_succ,
			ufm->stat.ibytes, ufm->stat.ibytes_succ);
	vlib_cli_output (vm, "opacket: %-16Lu opacket_succ: %-16Lu obytes: %-16Lu obytes_succ: %-16Lu", 
			ufm->stat.opackets, ufm->stat.opackets_succ,
			ufm->stat.obytes, ufm->stat.obytes_succ);
	vlib_cli_output (vm, "ierrors: %-16Lu oerrors: %-16Lu oerrors_full: %-16Lu", 
			ufm->stat.ierrors, ufm->stat.oerrors,
			ufm->stat.oerrors_full);
}

#define LIBUPAPP_IOCTL_CMD_DEBUG 	0x001
#define LIBUPAPP_IOCTL_CMD_OPEN_SNED 0x002
typedef struct _client_packet_info {
	int count;
	int length;
	dgram_hdr_t hdr;
}client_packet_info_t;

/* udp_fwd命令行实现函数 */
static clib_error_t *
udp_fwd_command_fn (vlib_main_t * vm, unformat_input_t * input,
			       vlib_cli_command_t * cmd)
{
	clib_error_t *error = 0;
	char* debug_flag;
	char* pcap_flags;
	int client_first_send_count = 0;
	int one_packet_length = 0;
	char* dst_ip_port = 0;
	while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
		if (unformat (input, "enable")) { /* udp_fwd enable命令 */
			udp46_fwd_enable(vm);
			goto cleanup;
		}
		else if (unformat (input, "disable")) { /* udp_fwd disable命令 */
			udp46_fwd_disable(vm);
			goto cleanup;
		}
		else if (unformat (input, "debug %s", &debug_flag)) {
			if (clib_strncmp(debug_flag, "on",  2) == 0) /* udp_fwd debug on命令 */
				debug_on = 1;
			else
				debug_on = 0;
			libupapp_ioctl(LIBUPAPP_IOCTL_CMD_DEBUG, (void*)&debug_on);
			vec_free(debug_flag);
		}
		else if (unformat (input, "stat")) {  /* udp_fwd stat命令 */
			udp_fwd_show_command_fn(vm);
			goto cleanup;
		}
		else if (unformat (input, "ul %d %d %s",  /* ul count len dst:ip/port命令  */
			&client_first_send_count, &one_packet_length, &dst_ip_port))
		{
			client_packet_info_t cinfo = {0};
			cinfo.count = client_first_send_count;
			cinfo.length = one_packet_length;
			u16 port = 0;
			unformat_input_t dst_ip_port_input, *dst_p = &dst_ip_port_input;
			{
				unformat_init_string (dst_p, dst_ip_port, strlen(dst_ip_port));
				if (unformat(dst_p, "dst:%U/%d",
			  		unformat_ip4_address, &cinfo.hdr.rmt_ip.ip4, &port)) {
			  		printf("[Note][%s:%d] dst port: %d\n", __func__, __LINE__, port);
			  		cinfo.hdr.rmt_port = htons(port);
			  	}
				cinfo.hdr.is_ip4 = 1;
			}
			vec_free(dst_ip_port);
			libupapp_ioctl(LIBUPAPP_IOCTL_CMD_OPEN_SNED, (void*)&cinfo);
		}
		else if (unformat (input, "pcap %s", &pcap_flags)) { /* udp_fwd pcap on/off命令 */
			if (clib_strncmp(pcap_flags, "on",  2) == 0)
				udp_fwd_main.pcap_flag = 1;
			else
				udp_fwd_main.pcap_flag = 0;
			const char* file_name = open_close_udp_fwd_pcap(NULL, udp_fwd_main.pcap_flag, 0);
			if (file_name)
				vlib_cli_output(vm, "pcap file: %s", file_name);
			vec_free(pcap_flags);
		}
		else
		{
			error = clib_error_return (0, "failed: unknown input `%U'",
					     format_unformat_error, input);
			goto cleanup;
		}
	}
cleanup:	
	return error;
}
/* 命令行实现，实现如下命令：
 * 1) udp_fwd enable/disable   ##启用此插件的udp转发功能
 * 2) udp_fwd debug on/off     ##日志开关
 * 3) udp_fwd stat             ##查看收发包统计
 * 4) udp_fwd ul count len dst:ip/port  ##在测试模块里，使用这个命令发送上行的报文
 * 5) udp_fwd pcap on/off      ##在此插件抓包功能的开关
 */
VLIB_CLI_COMMAND (udp_fwd_command, static) =
{
	.path = "udp_fwd",
	.short_help = "udp_fwd [enable|disable] [debug <on|off>] [stat]"
							"[ioctl ul <count> <len> <dst:ip/port>]"
							"[pcap on|off]",
	.function = udp_fwd_command_fn,
};

/* 只有加上这个定义，vpp在加载plugin时，才能加载此plugin
 * 可以使用命令show runtime命令查看当前加载所有的plugin
 */
/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () =
{
  .version = VPP_BUILD_VER,
  .description = "udp fwd Applications",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

/*
 * udp_fwd插件功能：
 * 1.使用VLIB_PLUGIN_REGISTER()定义vlib_plugin_registration_t类型的全局变量，并声明此全局变更代码段：.vlib_plugin_registration
 *   在vpp加载vpp/src/plugins/目录下的插件时，会校验此库是否有.vlib_plugin_registration代码段。
 * 2.使用VLIB_CLI_COMMAND()宏，定义并实现udp_fwd相关的命令。
 * 3.调用dlopen()加载libupapp.so库,调用dlsym()获取libupapp.so库向vpp开放的接口。
 * 4.转发下行的GTPU报文，接收2152端口的udp报文，代码文件：udp_fwd_dl.c
 *   4.1) 定义udp_fwd_dl_node节点，节点类型：interval；
 *   4.2) 从udp4/6_local_node节点接收报文；实现方法：通过调用udp_register_dst_port()函数实现；
 *   4.3) 调用接口libupapp_dl()将报文发送给libupapp.so库；
 *   4.4) 释放报文buffer，实现方法：调用vlib_buffer_free()函数实现；
 * 5.转发上行的GTPU报文，代码文件：udp_fwd_ul.c
 *   5.1) 定义udp_fwd_ul_node节点；节点类型：input;
 * 	 5.2) 从libupapp.so库中接收报文；
 *   5.3) 将报文从mbuf内存拷贝到vpp buffer；
 *   5.4) 在报文头部添加传输发和网络层头部；其中传输层目的端口为2152;
 *   5.5) 将报文转发给udp4/6_lookup_node节点
 *   5.6) 释放mbuf内存；
 */

