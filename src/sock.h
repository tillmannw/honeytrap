/* sock.h
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

#ifndef __HONEYTRAP_SOCK_H
#define __HONEYTRAP_SOCK_H 1

#define CONNTIMEOUT	90
#define FASTCONNTIMEOUT	3


int get_boundsock(struct sockaddr_in *server_addr, uint16_t port, int type);
int nb_connect(int sock_fd, const struct sockaddr * sockaddr, socklen_t slen, int sec);

#endif
