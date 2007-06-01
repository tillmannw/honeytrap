/* proxy.c
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

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

#include "honeytrap.h"
#include "proxy.h"
#include "logging.h"
#include "tcpip.h"

int proxy_connect(u_char mode, struct in_addr ipaddr, uint16_t l_port, u_int16_t port, uint16_t proto, Attack *attack) {
	int proxy_sock_fd, local_addr_len, flags, retval, error, sock_type;
	socklen_t len;
	struct sockaddr_in proxy_socket, local_socket;
	char *logstr=NULL, *Logstr=NULL, *logact=NULL, *logpre=NULL;
	struct timeval timeout;
	fd_set rfds, wfds;

	error = 0;
	sock_type = 0;

	if (attack == NULL) {
		logmsg(LOG_ERR, 1, "Error - No attack record to fill.\n");
		return(-1);
	}

	if (mode == PORTCONF_PROXY) {
		logact = strdup("proxy");
		logstr = strdup("server");
		Logstr = strdup("Server");
		logpre = strdup("==");
	} else if (mode == PORTCONF_MIRROR) {
		logact = strdup("mirror");
		logstr = strdup("mirror");
		Logstr = strdup("Mirror");
		logpre = strdup("<>");
	} else {
		logmsg(LOG_ERR, 1, "%s %s  Error - Mode %u for connection handling is not supported.\n",
			logpre, portstr, mode);
		return(-1);
	}

	/* prevent loops - disallow connections to localhost */
	if ((ntohl(ipaddr.s_addr) == 0x7F000001) && PORTCONF_MIRROR) {
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
		logmsg(LOG_ERR, 1, "%s %s  Error - Unable to create client socket for %s connection.\n",
			logpre, portstr, logact);
		return(-1);
	} else {
		logmsg(LOG_DEBUG, 1, "%s %s  Client socket for %s connection created.\n", logpre, portstr, logact);

		/* establish proxy connection */
		logmsg(LOG_DEBUG, 1, "%s %s  Establishing %s connection to %s:%u.\n",
			logpre, portstr, logact, inet_ntoa(ipaddr), port);

		bzero(&proxy_socket, sizeof(proxy_socket));
		proxy_socket.sin_family		= AF_INET;
		proxy_socket.sin_addr.s_addr	= ipaddr.s_addr;
		proxy_socket.sin_port		= htons(port);
		

		if (mode == PORTCONF_PROXY) {
			/* blocking connect() in proxy mode */
			if (connect(proxy_sock_fd, (struct sockaddr *) &proxy_socket, sizeof(proxy_socket)) != 0) {
				close(proxy_sock_fd);
				logmsg(LOG_DEBUG, 1, "%s %s  Unable to establish %s connection to %s:%d.\n",
					logpre, portstr, logact, inet_ntoa(ipaddr), port);
				return(-1);
			}
		} else if (mode == PORTCONF_MIRROR) {
	if (proto == TCP) {
			/* non-blocking connect() with short timeout to prevent simultane connection timeouts */
			logmsg(LOG_DEBUG, 1, "%s %s  Non-blocking, short-timeout connect to %s:%d.\n",
				logpre, portstr, inet_ntoa(ipaddr), port);
			flags = fcntl(proxy_sock_fd, F_GETFL, 0);

			if (fcntl(proxy_sock_fd, F_SETFL, flags | O_NONBLOCK) < 0) {
				fprintf(stderr, "Error in fcntl(): %s.\n", strerror(errno));
				logmsg(LOG_ERR, 1, "%s %s  Error - Unable to set mirror socket to non-blocking: %s.\n",
						logpre, portstr, strerror(errno));
				return(-1);
			}
			
			errno = 0;
			if ((retval = connect(proxy_sock_fd, (struct sockaddr *) &proxy_socket, sizeof(proxy_socket))) <0) {
				if (errno != EINPROGRESS) {
					logmsg(LOG_DEBUG, 1,
						"%s %s  Unable to establish mirror connection to %s:%d.\n",
						logpre, portstr, inet_ntoa(ipaddr), port);
					return(-1);
				}
			}
			
			if (retval != 0) {
				FD_ZERO(&rfds);
				FD_SET(proxy_sock_fd, &rfds);
				wfds = rfds;
				timeout.tv_sec = 3;
				timeout.tv_usec = 0;
				if (select(proxy_sock_fd+1, &rfds, &wfds, NULL, &timeout) == -1) {
					close(proxy_sock_fd);
					errno = ETIMEDOUT;
					logmsg(LOG_ERR, 1, "%s %s  Error - select() call failed: %s \n",
						logpre, portstr, strerror(errno));
					return(-1);
				}
				if (FD_ISSET(proxy_sock_fd, &rfds) || FD_ISSET(proxy_sock_fd, &wfds)) {
					len = sizeof(error);
					if (getsockopt(proxy_sock_fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
						logmsg(LOG_DEBUG, 1,
							"%s %s  Error - Mirror connection to %s:%d timed out.\n",
							logpre, portstr, inet_ntoa(ipaddr), port);
						return(-1);
					}
				} else {
					close(proxy_sock_fd);
					logmsg(LOG_DEBUG, 1, "%s %s  Unable to establish mirror connection: %s.\n",
						logpre, portstr, strerror(ETIMEDOUT));
					return(-1);
				}

			}
			fcntl(proxy_sock_fd, F_SETFL, flags);
			if (error) {
				close(proxy_sock_fd);
					logmsg(LOG_DEBUG, 1, "%s %s  Unable to establish mirror connection: %s.\n",
						logpre, portstr, strerror(error));
				return(-1);
			}
			} else if (proto == UDP) {
				if ((retval = connect(proxy_sock_fd,
					(struct sockaddr *) &proxy_socket, sizeof(proxy_socket))) <0) {
					if (errno != EINPROGRESS) {
						logmsg(LOG_DEBUG, 1,
							"%s %s  Unable to establish mirror connection to %s:%d.\n",
							logpre, portstr, inet_ntoa(ipaddr), port);
						return(-1);
					}
				}
			}
		}
		
		local_addr_len = 0;
		if (getsockname(proxy_sock_fd, (struct sockaddr *) &local_socket, (socklen_t *) &local_addr_len) != 0) {
			logmsg(LOG_ERR, 1, "%s %s  Error - Unable to get local address from %s socket: %s\n",
				logpre, portstr, logact, strerror(errno));
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
			logmsg(LOG_ERR, 1, "Error - Unable to allocate memory: %s\n", strerror(errno));
			close(from_fd);
			close(to_fd);
			return(-1);
		}
		memcpy(*save_string + offset, buffer, (*bytes_read));

		/* write read bytes to to_fd */
		*bytes_sent = 0;
		if ((*bytes_sent = write(to_fd, buffer, *bytes_read)) == -1) {
			logmsg(LOG_ERR, 1, "Unable to tcpcopy() %u bytes to target connection.\n", *bytes_read);
			close(from_fd);
			close(to_fd);
			return(-1);
		}
		return(*bytes_sent);
	}
	return(0);
}
