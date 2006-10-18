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

#include <pcap.h>
#include <netinet/in.h>

#include "ip.h"
#include "tcp.h"
#include "udp.h"
#include "attack.h"

int drop_privileges(void);
void start_dynamic_server(struct in_addr ip_r, uint16_t port_r, struct in_addr ip_l, uint16_t port_l, uint16_t proto);
int handle_connection_normal(int connection_fd, uint16_t port, u_char timeout, Attack *attack);
int handle_connection_proxied(int connection_fd, u_char mode, int server_sock_fd, uint16_t dport, uint16_t sport, struct in_addr ipaddr, u_char timeout, u_char fb_timeout, Attack *attack);


#endif
