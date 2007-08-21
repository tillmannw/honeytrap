/* response.h
 * Copyright (C) 2006 Tillmann Werner <tillmann.werner@gmx.de>
 *
 * This file is free software; as a special exception the author gives
 * unlimited permission to copy and/or distribute it, with or without
 * modifications, as long as this notice is preserved.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
 * implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * This code is based on an OpenSSL-compatible implementation of the RSA
 * Data Security, * Inc. MD5 Message-Digest Algorithm, written by Solar
 * Designer <solar at openwall.com> in 2001, and placed in the public
 * domain. There's absolutely no warranty. See md5.c for more information.
 */

#ifndef __HONEYTRAP_RESPONSE_H
#define __HONEYTRAP_RESPONSE_H

#include <netinet/in.h>

typedef struct def_resp {
	uint16_t port;
	uint16_t proto;
	uint32_t size;
	u_char *response;
	struct def_resp *next;
} def_resp;

def_resp *response_list;


void unload_default_responses(void);
int prepare_default_response(char *filename, uint16_t port, uint16_t proto);
int load_default_responses(char *dir);
int send_default_response(int connection_fd, uint16_t port, uint16_t proto, u_char timeout);

#endif
