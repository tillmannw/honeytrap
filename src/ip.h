/* ip.h
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

#ifndef __HONEYTRAP_IP_H
#define __HONEYTRAP_IP_H 1


/* IP header */
struct ip_header {
	u_char	ip_hlen:4, /* header length */
		ip_vers:4; /* version */
	u_char ip_tos; /* type of service */
	u_short ip_len; /* total length */
	u_short ip_id; /* identification */
	u_short ip_off; /* fragment offset field */
	u_char ip_ttl; /* time to live */
	u_char ip_p; /* protocol */
	u_short ip_sum; /* checksum */
	struct in_addr ip_src, ip_dst; /* source and dest address */
};

#define IP_RF 0x8000 /* reserved fragment flag */
#define IP_DF 0x4000 /* dont fragment flag */
#define IP_MF 0x2000 /* more fragments flag */
#define IP_OFFMASK 0x1fff /* mask for fragmenting bits */

#if BYTE_ORDER == BIG_ENDIAN
	#define ip_hl ip_vers 
	#define ip_v ip_hlen 
#else 
	#define ip_hl ip_hlen
	#define ip_v ip_vers
#endif

#define UDP		17
#define TCP		6
#define PROTO(p)	(p == TCP ? "tcp" : (p == UDP ? "udp" : "unknown"))

const struct ip_header *ip;


#endif
