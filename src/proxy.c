/* proxy.c
 * Copyright (C) 2006-2007 Tillmann Werner <tillmann.werner@gmx.de>
 *
 * This file is free software; as a special exception the author gives
 * unlimited permission to copy and/or distribute it, with or without
 * modifications, as long as this notice is preserved.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
 * implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>

#include "honeytrap.h"
#include "logging.h"
#include "proxy.h"
#include "signals.h"
#include "sock.h"
#include "tcpip.h"

int proxy_connect(u_char mode, struct in_addr ipaddr, uint16_t l_port, u_int16_t port, uint16_t proto, Attack *attack) {
	int proxy_sock_fd, local_addr_len, sock_type, timeout;
	struct sockaddr_in proxy_socket, local_socket;
	char *logact=NULL, *logpre=NULL;

	sock_type = 0;

	if (attack == NULL) {
		logmsg(LOG_ERR, 1, "Error - No attack record to fill.\n");
		return(-1);
	}

	if (mode == PORTCONF_PROXY) {
		logact = strdup("proxy");
		logpre = strdup("==");
	} else if (mode == PORTCONF_MIRROR) {
		logact = strdup("mirror");
		logpre = strdup("<>");
	} else {
		logmsg(LOG_ERR, 1, "%s %s  Error - Mode %u for connection handling is not supported.\n",
			logpre, portstr, mode);
		return(-1);
	}

	/* prevent loops - disallow mirror connections to localhost */
	if ((ntohl(ipaddr.s_addr) == 0x7F000001) && (mode == PORTCONF_MIRROR)) {
		logmsg(LOG_WARN, 1, "%s %s  Warning - Connection to %s:%u suppressed for loop prevention.\n",
			logpre, portstr, inet_ntoa(ipaddr), port);
		return(-1);
	}

	/* prepare client socket */

	logmsg(LOG_DEBUG, 1, "%s %s  Creating client socket for %s connection.\n", logpre, portstr, logact);
	if (proto == TCP) sock_type = SOCK_STREAM;
	else if (proto == UDP) sock_type = SOCK_DGRAM;
	else {
		logmsg(LOG_ERR, 1, "%s %s  Error - Protocol %d is not supported.\n",
			logpre, portstr, sock_type);
		return(-1);
	}	
	if (!(proxy_sock_fd = socket(AF_INET, sock_type, 0))) { 
		logmsg(LOG_ERR, 1, "%s %s  Error - Unable to create client socket for %s connection: %m.\n",
			logpre, portstr, logact);
		return(-1);
	} else {
		logmsg(LOG_DEBUG, 1, "%s %s  Client socket for %s connection created.\n", logpre, portstr, logact);

		// set keepalive option on connected socket
		int sockopt = 1;
		if (setsockopt(proxy_sock_fd, SOL_SOCKET, SO_KEEPALIVE, &sockopt, sizeof(sockopt)) < 0)
			logmsg(LOG_WARN, 1, "Warning - Unable to set SO_KEEPALIVE for socket.\n");

		/* establish proxy connection */
		logmsg(LOG_DEBUG, 1, "%s %s  Establishing %s connection to %s:%u.\n",
			logpre, portstr, logact, inet_ntoa(ipaddr), port);

		bzero(&proxy_socket, sizeof(proxy_socket));
		proxy_socket.sin_family		= AF_INET;
		proxy_socket.sin_addr.s_addr	= ipaddr.s_addr;
		proxy_socket.sin_port		= htons(port);
		

		timeout = (proto == TCP && PORTCONF_MIRROR) ? FASTCONNTIMEOUT : CONNTIMEOUT;
		switch(nb_connect(proxy_sock_fd, (struct sockaddr *) &proxy_socket,
		       sizeof(proxy_socket), timeout)) {
		case -1:
			switch(errno) {
			case EINPROGRESS:
				break;
			case EINTR:
				if (check_sigpipe() == -1) exit(EXIT_FAILURE);
				break;
			case ECONNREFUSED:
				logmsg(LOG_DEBUG, 1, "%s %s  select() call failed: %m.\n",
					logpre, portstr);
				return(-1);
			default:
				logmsg(LOG_ERR, 1, "%s %s  Error - select() call failed: %m.\n",
					logpre, portstr);
				return(-1);
			}
		case 0:
			logmsg(LOG_DEBUG, 1, "%s %s  Unable to establish %s connection: %s.\n",
				logpre, portstr, logact, strerror(ETIMEDOUT));
			return(-1);
		default:
			break;
		}
		
		local_addr_len = 0;
		if (getsockname(proxy_sock_fd, (struct sockaddr *) &local_socket, (socklen_t *) &local_addr_len) != 0) {
			logmsg(LOG_ERR, 1, "%s %s  Error - Unable to get local address from %s socket: %m.\n",
				logpre, portstr, logact);
			return(-1);
		}
		memcpy(&(attack->p_conn.l_addr), &local_socket.sin_addr, sizeof(uint32_t));
		memcpy(&(attack->p_conn.r_addr), &proxy_socket.sin_addr, sizeof(uint32_t));
		attack->p_conn.l_port	= local_socket.sin_port;
		attack->p_conn.r_port	= proxy_socket.sin_port;
	}
	return(proxy_sock_fd);
}

/* copy_data - reads data from one fd and writes it to another *
 * also stores read data in 'save_string' at position 'offset' */
int copy_data(int to_fd, int from_fd, u_char **save_string, uint32_t offset, int *bytes_read, int *bytes_sent) {
	u_char buffer[BUFSIZ];

	/* read from from_sock_fd */
	if ((*bytes_read = read(from_fd, buffer, sizeof(buffer))) > 0) {
		/* write read bytes to save_string at offset */
		if (!(*save_string = (u_char *) realloc(*save_string, offset+(*bytes_read)))) {
			logmsg(LOG_ERR, 1, "Error - Unable to allocate memory: %m.\n");
			close(from_fd);
			close(to_fd);
			return(-1);
		}
		memcpy(*save_string + offset, buffer, (*bytes_read));

		/* write read bytes to to_fd */
		*bytes_sent = 0;
		if ((*bytes_sent = write(to_fd, buffer, *bytes_read)) == -1) {
			logmsg(LOG_ERR, 1, "Error - Unable to tcpcopy() %u bytes to target connection: %m.\n", *bytes_read);
			close(from_fd);
			close(to_fd);
			return(-1);
		}
		return(*bytes_sent);
	}
	return(0);
}
