/* udp.h
 * Copyright (C) 2006 Tillmann Werner <tillmann.werner@gmx.de>
 *
 * This file is free software; as a special exception the author gives
 * unlimited permission to copy and/or distribute it, with or without
 * modifications, as long as this notice is preserved.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
 * implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */

#ifndef __HONEYTRAP_UDP_H
#define __HONEYTRAP_UDP_H 1


/* udp header */
struct udp_header{
	uint16_t	uh_sport;	/* udp source port */
	uint16_t	uh_dport;	/* udp dest port */
	uint16_t	uh_len;		/* datagram length */
	uint16_t	uh_sum;		/* udp checksum */
};

const struct udp_header *udp;

int udpsock(struct sockaddr_in *server_addr, uint16_t port);

#endif
