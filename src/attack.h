/* attack.h
 * Copyright (C) 2005-2008 Tillmann Werner <tillmann.werner@gmx.de>
 *
 * This file is free software; as a special exception the author gives
 * unlimited permission to copy and/or distribute it, with or without
 * modifications, as long as this notice is preserved.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
 * implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */

#ifndef __HONEYTRAP_ATTACK_H
#define __HONEYTRAP_ATTACK_H 1

#include <netinet/in.h>

struct s_payload {
	uint32_t		size;		/* length of attack string */
	char			md5sum[33];	/* md5 checksum */
	char			sha512sum[129];	/* sha512 checksum */
	u_char			*data;		/* attack string */
};

struct s_conn {
	uint32_t		l_addr;		/* local ip address */
	uint32_t		r_addr;		/* remote ip address */
	uint16_t		l_port;		/* local (tcp/udp) port */
	uint16_t		r_port;		/* remote (tcp/udp) port */
	u_char			protocol;	/* IP protocol id (tcp/udp) */
	struct s_payload	payload;	/* payload read from fd */
};

struct s_download {
	char			*dl_type;	/* (FTP, TFTP, VNC, ...) */
	uint32_t		r_addr;		/* remote IP address */
	uint32_t		l_addr;		/* local IP address */
	uint16_t		r_port;		/* remote port */
	uint16_t		l_port;		/* local port */
	uint16_t		protocol;	/* protocol as in IP header */
	char			*user;		/* username for download connection */
	char			*pass;		/* user's password */
	char			*filename;	/* filename of download */
	char			*uri;		/* unified resource identifier */
	struct s_payload	dl_payload;	/* downloaded data */
};

typedef struct s_attack {
	u_char			virtual;	/* flag for marking virtual attacks */
	time_t			start_time;	/* time of attack start */
	time_t			end_time;	/* time of attack end */
	struct s_conn		a_conn;		/* attack connection */
	struct s_conn		p_conn;		/* proxy/mirror connection */
	u_char			op_mode;	/* mode of operation (none, ignore, normal, proxy, mirror) */
	uint16_t		dl_count;	/* number of downloads */
	uint16_t		dl_tries;	/* number of download tries */
	struct s_download	*download;	/* array of download structs */
} Attack;


Attack *new_virtattack(struct in_addr l_addr, struct in_addr r_addr, uint16_t l_port, uint16_t r_port, uint16_t proto);
Attack *new_attack(struct in_addr l_addr, struct in_addr r_addr, uint16_t l_port, uint16_t r_port, uint16_t proto);
void del_attack(Attack *a);
int process_data(u_char *a_data, uint32_t a_size, u_char *p_data, uint32_t p_size, uint16_t port, Attack *a);
int add_download(const char *dl_type, u_int16_t proto, const uint32_t r_addr, const uint16_t r_port, const char *user, const char *pass, const char *filename, const char *uri, const u_char *data, const u_int32_t size, Attack *a);
int reassign_downloads(Attack *dst, Attack *src);

#endif
