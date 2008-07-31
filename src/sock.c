/* sock.c
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

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "honeytrap.h"
#include "ipqmon.h"
#include "logging.h"
#include "nfqmon.h"
#include "signals.h"
#include "sock.h"
#include "tcpip.h"


/* returns a bound socket matching a connection request *
 * sets verdict on request packet if ipq or nfq was used and the port is already bound *
 * in the latter case, -1 is returned */
int get_boundsock(struct sockaddr_in *server_addr, uint16_t port, int type) {
	int fd, sockopt;
#ifdef USE_IPQ_MON
	int status;
#endif

	if ((type != SOCK_DGRAM) && (type != SOCK_STREAM)) {
	    logmsg(LOG_ERR, 1, "Error - Socket type %d not supported.\n", type);
	    exit(EXIT_FAILURE);
	}

	if (!(fd = socket(AF_INET, type, 0))) {
	    logmsg(LOG_ERR, 1, "Error - Could not create socket: %m.\n");
	    exit(EXIT_FAILURE);
	}

	sockopt = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof(sockopt)) < 0)
		logmsg(LOG_WARN, 1, "Warning - Unable to set SO_REUSEADDR for server socket.\n");

	bzero((char *) server_addr, sizeof(struct sockaddr_in));
	server_addr->sin_family		= AF_INET;
	server_addr->sin_addr.s_addr	= bind_address.s_addr;
	server_addr->sin_port		= port;
	if ((bind(fd, (struct sockaddr *) server_addr, sizeof(struct sockaddr_in))) != 0) {
	    /* we already got one server process */
	    logmsg(LOG_DEBUG, 1, "Unable to bind to port %u/tcp: %m.\n", ntohs(port));
#ifdef USE_IPQ_MON
	    /* hand packet processing back to the kernel */
	    if ((status = ipq_set_verdict(h, packet->packet_id, NF_ACCEPT, 0, NULL)) < 0) {
		logmsg(LOG_ERR, 1, "Error - Could not set verdict on packet: %s.\n", ipq_errstr());
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

	    /* a dynamic server is already present */
	    close(fd);
	    return(-1);
#else
	    /* if bind() did not fail for 'port already in use' but for some other reason,
	     *  we're in troubles and want a verbose error message */
	    if (errno != 98) logmsg(LOG_NOISY, 1, "Warning - Could not bind to port %u/tcp: %m.\n", ntohs(port));
	    exit(EXIT_FAILURE);
#endif
#endif
	}
	logmsg(LOG_DEBUG, 1, "Socket created, file descriptor is %d.\n", fd);

	return(fd);
}


/* perform a non-blocking connect() with a given timeout
 * always use this function instead of connect()
 * or signal processing might get delayed */
int nb_connect(int sock_fd, const struct sockaddr * sockaddr, socklen_t slen, int sec) {
	int		flags, rv, error;
	struct timeval	timeout;
	fd_set		rfds, wfds;
	socklen_t	len;

	flags		 = 0;

	/* safe fd flags and set socket to non-blocking */
	if ((flags = fcntl(sock_fd, F_GETFL, 0) < 0)) return(-1);
	if (fcntl(sock_fd, F_SETFL, flags | O_NONBLOCK) < 0) return(-1);
	
	/* try an immediate connect */
	errno	= 0;
	error	= 0;
	if ((rv = connect(sock_fd, sockaddr, slen)) < 0) 
		if (errno != EINPROGRESS) return(-1);
	
	if (rv != 0) {
		/* do a non-blocking connect */
		FD_ZERO(&rfds);
		FD_SET(sigpipe[0], &rfds);
		FD_SET(sock_fd, &rfds);

		wfds		= rfds;
		timeout.tv_sec	= sec;
		timeout.tv_usec	= 0;

		switch (select(MAX(sigpipe[0], sock_fd) + 1, &rfds, &wfds, NULL, &timeout)) {
		case -1:
			if (errno == EINPROGRESS) break;
			if (errno == EINTR) {
				if (check_sigpipe() == -1) exit(EXIT_FAILURE);
				break;
			}
			close(sock_fd);
			errno = ETIMEDOUT;
			return(-1);
		case 0:
			/* timeout */
			close(sock_fd);
			errno = ETIMEDOUT;
			return(0);
		default:
			if (FD_ISSET(sigpipe[0], &rfds) && (check_sigpipe() == -1)) {
				logmsg(LOG_ERR, 1, "Error - Signal handling failed in dynamic server process.\n");
				exit(EXIT_FAILURE);
			}
			if (FD_ISSET(sock_fd, &rfds) || FD_ISSET(sock_fd, &wfds)) {
				len	= sizeof(error);
				if (getsockopt(sock_fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0) return(-1);
				if (error) {
					errno = error;
					return(-1);
				}
			}
		}
	}
	if (fcntl(sock_fd, F_SETFL, flags) < 0) return(-1);
	if (error) {
		errno = error;
		return(-1);
	}

	return(sock_fd);
}
