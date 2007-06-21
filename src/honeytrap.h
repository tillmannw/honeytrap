/* honeytrap.h
 * Copyright (C) 2005-2007 Tillmann Werner <tillmann.werner@gmx.de>
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

#if HAVE_CONFIG_H
# include <config.h>
#endif

#define MAX(a, b)	(a > b ? a : b)
#define MIN(a, b)	(a < b ? a : b)

#define EXCL_FILE_RW	O_CREAT | O_NOCTTY | O_APPEND | O_WRONLY

#define PORTCONF_NONE	0
#define PORTCONF_NORMAL	1
#define PORTCONF_IGNORE	2
#define PORTCONF_MIRROR	4
#define PORTCONF_PROXY	8
#define MODE(m)		(m == PORTCONF_NONE ? "none" : (m == PORTCONF_NORMAL ? "normal" : (m == PORTCONF_IGNORE ? "ignore" : (m == PORTCONF_MIRROR ? "mirror" : (m == PORTCONF_PROXY ? "proxy" : "unknown")))))

char *conffile_name, **arg_v;
int arg_c;

// global variables regarding configuration

char	*pidfile_name;
char	*logfile_name;
char	*dev;
char	*response_dir;
char	*plugin_dir;
int	daemonize;
int	promisc_mode;
uid_t	u_id;
gid_t	g_id;
int32_t	conn_timeout;
int32_t	read_timeout;
int32_t	m_read_timeout;
int32_t read_limit;

/* explicit port configurations */
u_char	portconf_default;

typedef struct sport_flag {
	u_int8_t tcp;
	u_int8_t udp;
} port_flag;

port_flag port_flags[0x10000];

// end of global config variables

int pidfile_fd, first_init;
pid_t parent_pid;
char old_cwd[1024];


#endif
