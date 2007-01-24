/* attack.h
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

#ifndef __HONEYTRAP_ATTACK_H
#define __HONEYTRAP_ATTACK_H 1

#include <netinet/in.h>

struct s_payload {
	uint32_t	size;
	char		chksum[33];	/* md5 checksum */
	u_char		*data;
};

struct s_conn {
	uint32_t		l_addr;		/* local ip address */
	uint32_t		r_addr;		/* remote ip address */
	uint16_t		l_port;		/* local (tcp/udp) port */
	uint16_t		r_port;		/* remote (tcp/udp) port */
	uint32_t		protocol;	/* protocol id (tcp/udp) */
	struct s_payload	payload;	/* payload read from fd */
};

typedef struct s_attack {
	time_t		start_time;	/* time of attack start */
	time_t		end_time;	/* time of attack end */
	struct s_conn	a_conn;		/* attack connection */
	struct s_conn	p_conn;		/* proxy/mirror connection */
	u_char		op_mode;	/* mode of operation (none, ignore, normal, proxy, mirror) */
} Attack;


Attack *new_attack(struct in_addr l_addr, struct in_addr r_addr, uint16_t l_port, uint16_t r_port, uint16_t proto);
int process_data(u_char *a_data, uint32_t a_size, u_char *p_data, uint32_t p_size, uint16_t port, Attack *a);


#endif
