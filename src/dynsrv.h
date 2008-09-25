/* dynsrv.h
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

#ifndef __HONEYTRAP_DYNSRV_H
#define __HONEYTRAP_DYNSRV_H 1

#include <netinet/in.h>
#ifdef USE_PCAP_MON
#  include <pcap.h>
#endif

#include "attack.h"
#include "queue.h"
#include "tcpip.h"

int	portinfopipe[2];	// IPC pipe, used by connection handlers to 'register' ports in the master process, these are then handled in ignore mode
queue	*portinfoq;		// queue for registered port information

typedef struct {
	u_int16_t	port;
	u_char		protocol;
	int		mode;
//	struct in_addr	host;
} portinfo;


int drop_privileges(void);
void start_dynamic_server(struct in_addr ip_r, uint16_t port_r, struct in_addr ip_l, uint16_t port_l, uint16_t proto);
int handle_connection_normal(int connection_fd, uint16_t port, uint16_t proto, u_char timeout, Attack *attack);
int handle_connection_proxied(int connection_fd, u_char mode, int server_sock_fd, uint16_t dport, uint16_t sport, struct in_addr ipaddr, uint16_t proto, u_char timeout, u_char fb_timeout, Attack *attack);
int check_portinfopipe(void);


#endif
