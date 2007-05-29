/* tcp.c
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

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <netdb.h>
#include <string.h>

#include "honeytrap.h"
#include "logging.h"
#include "ipqmon.h"
#include "nfqmon.h"
#include "tcp.h"

#ifdef USE_IPQ_MON
#include <linux/netfilter.h>
#endif


int tcpsock(struct sockaddr_in *server_addr, uint16_t port) {
	int fd, sockopt;
#ifdef USE_IPQ_MON
	int status;
#endif

	if (!(fd = socket(AF_INET, SOCK_STREAM, 0))) {
	    logmsg(LOG_ERR, 1, "Error - Could not create tcp socket: %s\n", strerror(errno));
	    return(-1);
	}

	sockopt = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof(sockopt)) < 0)
		logmsg(LOG_WARN, 1, "Warning - Unable to set SO_REUSEADDR on listening socket.\n");

	bzero((char *) server_addr, sizeof(struct sockaddr_in));
	server_addr->sin_family		= AF_INET;
	server_addr->sin_addr.s_addr	= htonl(INADDR_ANY);
	server_addr->sin_port		= port;
	if ((bind(fd, (struct sockaddr *) server_addr, sizeof(struct sockaddr_in))) < 0) {
	    /* we already got one server process */
	    logmsg(LOG_DEBUG, 1, "Warning - Unable to bind port %d/tcp: %s.\n", ntohs(port), strerror(errno));
#ifdef USE_IPQ_MON
	    /* hand packet processing back to the kernel */
	    if ((status = ipq_set_verdict(h, packet->packet_id, NF_ACCEPT, 0, NULL)) < 0) {
		logmsg(LOG_ERR, 1, "Error - Could not set verdict on packet.\n");
		logmsg(LOG_ERR, 1, "IPQ Error: %s.\n", ipq_errstr());
		ipq_destroy_handle(h);
		exit(EXIT_FAILURE);
	    }
	    logmsg(LOG_DEBUG, 1, "IPQ - Successfully set verdict on packet.\n");
	    return(-1);
#else
#ifdef USE_NFQ_MON
	    /* hand packet processing back to the kernel */
	    /* nfq_set_verdict()'s return value is undocumented,
	     * but digging the source of libnetfilter_queue and libnfnetlink reveals
	     * that it's just the passed-through value of a sendmsg() */
	    if (nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL) == -1) {
		logmsg(LOG_ERR, 1, "Error - Could not set verdict on packet.\n");
		nfq_destroy_queue(qh);
		exit(EXIT_FAILURE);
	    }
	    logmsg(LOG_DEBUG, 1, "NFQ - Successfully set verdict on packet.\n");
	    return(-1);
#else
	    if (errno != 98)
		    logmsg(LOG_NOISY, 1, "Warning - Could not bind to port %u/tcp: %s.\n", ntohs(port), strerror(errno));
	    else
		    logmsg(LOG_DEBUG, 1, "Warning - Could not bind to port %u/tcp: %s.\n", ntohs(port), strerror(errno));
	    close(fd);
	    return(-1);
#endif
#endif
	}
	return(fd);
}


/* tcpcopy - reads data from one connection and writes it to another *
 * also store read data in 'save_string' at position 'offset' */
int tcpcopy(int to_fd, int from_fd, u_char **save_string, uint32_t offset, int *bytes_read, int *bytes_sent) {
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

		/* write read bytes to to_sock_fd */
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
