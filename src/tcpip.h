/* tcpip.h
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

#ifndef __HONEYTRAP_TCPIP_H
#define __HONEYTRAP_TCPIP_H 1

#include <netinet/in.h>


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


/* udp header */
struct udp_header{
	uint16_t	uh_sport;	/* udp source port */
	uint16_t	uh_dport;	/* udp dest port */
	uint16_t	uh_len;		/* datagram length */
	uint16_t	uh_sum;		/* udp checksum */
};

/* tcp header */
struct tcp_header{
	uint16_t	th_sport;	/* tcp source port */
	uint16_t	th_dport;	/* tcp dest port */
	uint32_t	th_seqno;	/* tcp sequence number,identifies the byte in the stream of data */
	uint32_t	th_ackno;	/* contains the next seq num that the sender expects to recieve */
	u_char		th_res:4,	/* 4 reserved bits */
			th_doff:4;	/* data offset */
	u_char		th_flags;	/* tcp flags */
	uint16_t	th_window;	/* maxinum number of bytes able to recieve*/
	uint16_t	th_sum;		/* checksum to cover the tcp header and data portion of the packet*/
	uint16_t	th_urp;		/* vaild only if the urgent flag is set, used to transmit emergency data */
};

#define FIN 0x01
#define SYN 0x02
#define RST 0x04
#define PUSH 0x08
#define ACK 0x10
#define URG 0x20
#define ECE 0x40
#define CWR 0x80
#define FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)


#define RAW		0
#define ICMP		1
#define TCP		6
#define UDP		17
#define PROTO(p)	(p == RAW ? "raw" : (p == ICMP ? "icmp" : (p == TCP ? "tcp" : (p == UDP ? "udp" : "unknown"))))


const struct ip_header *ip;
const struct udp_header *udp;
const struct tcp_header *tcp;


#endif
