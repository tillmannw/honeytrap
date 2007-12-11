/* util.h
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

#ifndef __HONEYTRAP_UTIL_H
#define __HONEYTRAP_UTIL_H 1

#define MAX_LINE 1024
#define READ_SIZE 1440

struct strtk {
	char *string;
	int offset;
};

typedef struct {
	u_int32_t len;
	u_char *data;
} bstr;

/* rfc1918 prefixes */
static const uint32_t priv_prefixes[] = {
	0x0affffff,	// 10.x.x.x
	0xac1fffff,	// 172.16.x.x - 172.31.x.x
	0xc0a8ffff	// 192.168.x.x
};


int valid_ipaddr(struct in_addr address);
int private_ipaddr(struct in_addr address);
int read_line(int socket, char *line, ssize_t len, int timeout);
struct strtk extract_token(char *parse_string);
char *get_next_line(FILE * file);

#endif
