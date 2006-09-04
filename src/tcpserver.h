/* tcpserver.h
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

#ifndef __HONEYTRAP_TCPSRV_H
#define __HONEYTRAP_TCPSRV_H 1

#include <pcap.h>
#include <netinet/in.h>

#include "honeytrap.h"

#ifndef ETHER_HDRLEN
 #define ETHER_HDRLEN 14
#endif


struct s_payload {
	uint32_t	size;
	char		chksum[33];
	u_char		*data;
};

struct s_conn {
	struct in_addr		l_addr;		/* local ip address */
	struct in_addr		r_addr;		/* remote ip address */
	uint16_t		l_port;		/* local (tcp) port */
	uint16_t		r_port;		/* remote (tcp) port */
	uint32_t		protocol;	/* protocol id */
	uint32_t		flags;		/* flags (frag, etc) */
	struct s_payload	payload;	/* payload read from fd */
};

typedef struct s_attack {
	time_t		start_time;	/* time of attack start */
	time_t		end_time;	/* time of attack end */
	struct s_conn	a_conn;		/* attack connection */
	struct s_conn	m_conn;		/* mirror connection */
	struct s_conn	p_conn;		/* proxy connection */
} Attack;

Attack attack;

/* IP header */
struct ip_header {
    u_char	ip_hlen:4, /* header length */
    		ip_vers:4; /* version */
    u_char ip_tos; /* type of service */
    u_short ip_len; /* total length */
    u_short ip_id; /* identification */
    u_short ip_off; /* fragment offset field */
    #define IP_RF 0x8000 /* reserved fragment flag */
    #define IP_DF 0x4000 /* dont fragment flag */
    #define IP_MF 0x2000 /* more fragments flag */
    #define IP_OFFMASK 0x1fff /* mask for fragmenting bits */
    u_char ip_ttl; /* time to live */
    u_char ip_p; /* protocol */
    u_short ip_sum; /* checksum */
    struct in_addr ip_src,ip_dst; /* source and dest address */
};

#if BYTE_ORDER == BIG_ENDIAN
	#define ip_hl ip_vers 
	#define ip_v ip_hlen 
#else 
	#define ip_hl ip_hlen
	#define ip_v ip_vers
#endif

/* tcp header */
struct tcp_header{
	uint16_t	th_sport;	/* tcp source port */
	uint16_t	th_dport;	/* tcp dest port */
	uint32_t	th_seqno;	/* tcp sequence number,identifies the byte in the stream of data */
	uint32_t	th_ackno;	/* contains the next seq num that the sender expects to recieve */
	u_char		th_res:4,	/* 4 reserved bits */
			th_doff:4;	/* data offset */
	u_char		th_flags;
			#define FIN 0x01
			#define SYN 0x02
			#define RST 0x04
			#define PUSH 0x08
			#define ACK 0x10
			#define URG 0x20
			#define ECE 0x40
			#define CWR 0x80
			#define FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	uint16_t	th_window;	/* maxinum number of bytes able to recieve*/
	uint16_t	th_sum;		/* checksum to cover the tcp header and data portion of the packet*/
	uint16_t	th_urp;		/* vaild only if the urgent flag is set, used to transmit emergency data */
};

const struct ip_header *ip;
const struct tcp_header *tcp;


int drop_privileges(void);
void save_record(const u_char *attack_string, int total_bytes, const struct ip_header *ip, const struct tcp_header *tcp);
void start_tcp_server(struct in_addr ip_r, u_int16_t port_r, struct in_addr ip_l, u_int16_t port_l);
int handle_connection_normal(int connection_fd, uint16_t port, u_char timeout);
int handle_connection_proxied(int connection_fd, u_char mode, int server_sock_fd, uint16_t dport, uint16_t sport, struct in_addr ipaddr, u_char timeout, u_char fb_timeout);
int process_data(u_char *a_data, uint32_t a_size, u_char *m_data, uint32_t m_size, uint16_t port);
void init_attack(int fd, struct in_addr l_addr, struct in_addr r_addr, uint16_t l_port, uint16_t r_port);
int tcpcopy(int to_sock_fd, int from_sock_fd, u_char **save_string, uint32_t offset, int *bytes_read, int *bytes_sent);

#endif
