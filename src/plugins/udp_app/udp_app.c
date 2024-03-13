/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *	   http://www.apache.org/licenses/LICENSE-2.0
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
#include "load_libudpapp.h"

unsigned char debug_on = 1;
udpapp_main_t udpapp_main = {0};

clib_error_t * register_udp46_port(vlib_main_t * vm, u16 udp_port);
clib_error_t * unregister_udp46_port(vlib_main_t * vm, u16 udp_port);

static int init_udpapp(void)
{
	load_libudpapp();
	libudpapp_init();
	libudpapp_set_egress(udpapp_egress_xmit);
	return 0;
}

static void uninit_udpapp(void)
{
	libudpapp_uninit();
	unlod_libudpapp();
}

static void udp46_app_enable(vlib_main_t * vm, u16 udp_port)
{
	udpapp_main_t *ufm = &udpapp_main;
	if (ufm->create_flag == 1) 
		return ;
	ufm->udp_port = udp_port;	
	register_udp46_port(vm, udp_port);
	udpapp_egress_init(vm);
	init_udpapp(); /* load libudpapp.so library */
	ufm->create_flag = 1;
	return ;
}

static void udp46_app_disable(vlib_main_t * vm)
{	
	udpapp_main_t *ufm = &udpapp_main;
	unregister_udp46_port(vm, ufm->udp_port);
	uninit_udpapp();
	udpapp_egress_uninit(vm);
	memset(&udpapp_main, 0, sizeof(udpapp_main));
}

static void
udpapp_show_command_fn (vlib_main_t * vm)
{
	udpapp_main_t *ufm = &udpapp_main;
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

#define LIBUDPAPP_IOCTL_CMD_DEBUG	0x001
#define LIBUDPAPP_IOCTL_CMD_OPEN_SNED 0x002
typedef struct _client_packet_info {
	int count;
	int length;
	dgram_hdr_t hdr;
}client_packet_info_t;

static clib_error_t *
udpapp_command_fn (vlib_main_t * vm, unformat_input_t * input,
				   vlib_cli_command_t * cmd)
{
	clib_error_t *error = 0;
	char* debug_flag;
	char* pcap_flags;
	int client_first_send_count = 0;
	int one_packet_length = 0;
	char* dst_ip_port = 0;
	u16 udp_port = 2152;
	while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
		if (unformat (input, "enable %d", &udp_port)) { /* udpapp enable <udp port> */
			udp46_app_enable(vm, udp_port);
			goto cleanup;
		}
		else if (unformat (input, "disable")) { /* udpapp disable */
			udp46_app_disable(vm);
			goto cleanup;
		}
		else if (unformat (input, "debug %s", &debug_flag)) {
			if (clib_strncmp(debug_flag, "on",	2) == 0) /* udpapp debug on */
				debug_on = 1;
			else
				debug_on = 0;
			libudpapp_ioctl(LIBUDPAPP_IOCTL_CMD_DEBUG, (void*)&debug_on);
			vec_free(debug_flag);
		}
		else if (unformat (input, "stat")) {  /* udpapp stat */
			udpapp_show_command_fn(vm);
			goto cleanup;
		}
		else if (unformat (input, "egress %d %d %s",  /* udpapp egress count len dst:ip/port  */
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
			libudpapp_ioctl(LIBUDPAPP_IOCTL_CMD_OPEN_SNED, (void*)&cinfo);
		}
		else if (unformat (input, "pcap %s", &pcap_flags)) { /* udpapp pcap on/off */
			if (clib_strncmp(pcap_flags, "on",	2) == 0)
				udpapp_main.pcap_flag = 1;
			else
				udpapp_main.pcap_flag = 0;
			const char* file_name = open_close_udpapp_pcap(NULL, udpapp_main.pcap_flag, 0);
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

VLIB_CLI_COMMAND (udpapp_command, static) =
{
	.path = "udpapp",
	.short_help = "udpapp [enable <udp_port>|disable]"
							"[debug <on|off>] [stat]"
							"[ioctl ul <count> <len> <dst:ip/port>]"
							"[pcap on|off]",
	.function = udpapp_command_fn,
};

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () =
{
  .version = VPP_BUILD_VER,
  .description = "udp app Applications",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

