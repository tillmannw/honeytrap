/* proxy.h
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

#ifndef __HONEYTRAP_PROXY_H
#define __HONEYTRAP_PROXY_H 1

#include <sys/types.h>

#include "attack.h"

int proxy_connect(u_char mode, struct in_addr ipaddr, uint16_t l_port, u_int16_t port, uint16_t proto, Attack *attack);
int copy_data(int to_fd, int from_fd, u_char **save_string, uint32_t offset, int *bytes_read, int *bytes_sent);

#endif
