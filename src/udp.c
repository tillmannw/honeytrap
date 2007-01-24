/* udp.c
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

#include <stdlib.h>
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
#include "udp.h"

#ifdef USE_IPQ_MON
#include <linux/netfilter.h>
#endif


int udpsock(struct sockaddr_in *server_addr, uint16_t port) {
	int fd, sockopt;
#ifdef USE_IPQ_MON
	int status;
#endif

	if (!(fd = socket(AF_INET, SOCK_DGRAM, 0))) {
	    logmsg(LOG_ERR, 1, "Error - Could not create udp socket: %s\n", strerror(errno));
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
#ifdef USE_IPQ_MON
	    /* hand packet processing back to the kernel */
	    if ((status = ipq_set_verdict(h, packet->packet_id, NF_ACCEPT, 0, NULL)) < 0) {
		logmsg(LOG_ERR, 1, "Error - Could not set verdict on packet.\n");
		logmsg(LOG_ERR, 1, "IPQ Error: %s.\n", ipq_errstr());
		ipq_destroy_handle(h);
		exit(1);
	    }
	    return(-1);
#else
	    if (errno != 98)
		    logmsg(LOG_NOISY, 1, "Warning - Could not bind to port %u/udp: %s.\n", ntohs(port), strerror(errno));
	    else
		    logmsg(LOG_DEBUG, 1, "Warning - Could not bind to port %u/udp: %s.\n", ntohs(port), strerror(errno));
	    close(fd);
	    return(-1);
#endif
	}
	return(fd);
}
