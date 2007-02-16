/* honeytrap.h
 * Copyright (C) 2005-2006 Tillmann Werner <tillmann.werner@gmx.de>
 *
 * This file is free software; as a special exception the author gives
 * unlimited permission to copy and/or distribute it, with or without
 * modifications, as long as this notice is preserved.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
 * implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */

#ifndef __HONEYTRAP_MAIN_H
#define __HONEYTRAP_MAIN_H 1

#include <sys/types.h>
#include <netinet/in.h>
#include <pwd.h>
#include <grp.h>
#include <dlfcn.h>
#ifdef USE_PCAP_MON
#  include <pcap.h>
#endif

#if HAVE_CONFIG_H
# include <config.h>
#endif


#define EXCL_FILE_RW	O_CREAT | O_NOCTTY | O_APPEND | O_WRONLY
#define DEBUG_FPRINTF if (log_level == LOG_DEBUG) fprintf

#define PORTCONF_NONE	0
#define PORTCONF_NORMAL	1
#define PORTCONF_IGNORE	2
#define PORTCONF_MIRROR	4
#define PORTCONF_PROXY	8

#define TCP 	6
#define UDP	17

char *conffile_name, **arg_v;
int arg_c;

// global variables regarding configuration

char *pidfile_name;
char *logfile_name;
char *dbfile_name;
char *dev;
char *response_dir;
char *plugin_dir;
char *attacks_dir;
char *dlsave_dir;
char *ftp_host;
int daemonize;
int mirror_mode;
int promisc_mode;
uid_t u_id;
gid_t g_id;
uint32_t conn_timeout;
uint32_t read_timeout;
uint32_t m_read_timeout;
uint32_t read_limit;


/* struct for destinationa if connection is handled in proxy mode */
struct s_proxy_dest {
	uint16_t		attack_port;
	char			*d_addr;
	uint16_t		d_port;
	struct s_proxy_dest	*next;
};

/* explicit port configurations */
typedef struct sport_flag {
	u_int8_t tcp;
	u_int8_t udp;
} port_flag;

port_flag port_flags[0x10000];
struct s_proxy_dest *proxy_dest;

// end of global config variables

int pidfile_fd, first_init;
pid_t parent_pid;
char old_cwd[1024];

#ifdef USE_PCAP_MON
char *bpf_filter_string;
bpf_u_int32 mask;
bpf_u_int32 net;

pcap_t *packet_sniffer;
u_char pcap_offset;
#endif


#endif
