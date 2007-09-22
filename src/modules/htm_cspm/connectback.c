/* connectback.c
 * Copyright (C) 2007 Tillmann Werner <tillmann.werner@gmx.de>
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
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <logging.h>

#include "attack.h"
#include "connectback.h"
#include "honeytrap.h"
#include "sc_action.h"
#include "signals.h"
#include "sock.h"
#include "tcpip.h"


int connectback(struct sc_action* sa, int haskey) {
	int			sockfd, t, bytes_read, total_bytes;
	fd_set			rfds;
	struct timeval		st;
	struct sockaddr_in	sock;
	u_char			buffer[BUFSIZ], *attack_string;
	Attack			*a;

	if ((a = new_virtattack(*(struct in_addr*) &sa->m_localhost, *(struct in_addr*) &sa->m_action.m_connectback.m_remotehost,
				0, sa->m_action.m_connectback.m_remoteport, TCP)) == NULL) {
		logmsg(LOG_ERR, 1, "CSPM Error - Unable to create virtual attack for connectback session.\n");
		exit(EXIT_FAILURE);
	}

	/* prepare connect socket */
	if ((sockfd = socket(PF_INET, SOCK_STREAM, 0)) == -1) {
		logmsg(LOG_ERR, 1, "CSPM Error - Could not create connectback socket: %s.\n", strerror(errno));
		exit(1);
	}
	bzero(&sock, sizeof(sock));
	sock.sin_family		= AF_INET;
	sock.sin_addr.s_addr	= *(&sa->m_action.m_connectback.m_remotehost);
	sock.sin_port		= htons(sa->m_action.m_connectback.m_remoteport);

	logmsg(LOG_NOISY, 1, "CSPM - Connecting back to %s:%u/tcp.\n",
		inet_ntoa(*(struct in_addr*) &sa->m_action.m_connectback.m_remotehost), sa->m_action.m_connectback.m_remoteport);
	if (!nb_connect(sockfd, (struct sockaddr *) &sock, sizeof(sock), 6)) {
		logmsg(LOG_ERR, 1, "CSPM Error - Could not connect back to %s:%d: %s.\n",
			inet_ntoa(*(struct in_addr *)&sa->m_action.m_connectback.m_remotehost),
			sa->m_action.m_connectback.m_remoteport, strerror(errno));
		errno = 0;
		return(0);
	}
	logmsg(LOG_INFO, 1, "CSPM - Successfully connected back to %s:%d.\n",
			inet_ntoa(*(struct in_addr *)&sa->m_action.m_connectback.m_remotehost),
			sa->m_action.m_connectback.m_remoteport);

	/* set virtual attack infos */
	a->a_conn.l_addr	= sa->m_localhost;
	a->a_conn.r_addr	= sa->m_action.m_connectback.m_remotehost;
	a->a_conn.r_port	= sa->m_action.m_connectback.m_remoteport;
	a->a_conn.protocol	= TCP;

	/* send key */
	if (haskey) {
logmsg(LOG_INFO, 1, "CSPM - Sending key.\n");
		if (write(sockfd, &sa->m_action.m_connectback.m_key, sizeof(sa->m_action.m_connectback.m_key)) <
			sizeof(sa->m_action.m_connectback.m_key)) { 
			logmsg(LOG_ERR, 1, "CSPM Error - Unable to send connectback key: %s.\n", strerror(errno));
			close(sockfd);
			return(0);
		}
		logmsg(LOG_NOISY, 1, "CSPM - Connectback key sent.\n");
	}

	/* read data */
	for(;;) {
		FD_ZERO(&rfds);
		FD_SET(sockfd, &rfds);

		st.tv_sec  = 10;
		st.tv_usec = 0;

		switch (t = select(MAX(sigpipe[0], sockfd), &rfds, NULL, NULL, &st)) {
		case -1:
			fprintf(stderr, "Error with select(): %s.\n", strerror(errno));
			exit(1);
		case  0:
			break;
		default:
			if (FD_ISSET(sigpipe[0], &rfds) && (check_sigpipe() == -1)) {
				logmsg(LOG_ERR, 1, "Error - Signal handling failed in dynamic server process.\n");
				exit(EXIT_FAILURE);
			}
			if (FD_ISSET(sockfd, &rfds)) { 
				if ((bytes_read = read(sockfd, buffer, BUFSIZ)) < 0) { 
					logmsg(LOG_ERR, 1, "CSPM - Error while reading data from connectback socket: %s.\n",
						strerror(errno));
					close(sockfd);
					return(0);
				}
				if (bytes_read == 0) {
					logmsg(LOG_INFO, 1, "CSPM - Connectback socket closed by remote host.\n");
					close(sockfd);
					return(1);
				}
				break;
				/* handle data on connection */
				if ((bytes_read = read(sockfd, buffer, BUFSIZ)) > 0) {
					logmsg(LOG_DEBUG, 1, "CSPM - %d bytes read.\n", bytes_read);
					total_bytes += bytes_read;
					if (!(attack_string = (u_char *) realloc(attack_string, total_bytes))) {
						logmsg(LOG_ERR, 1, "CSPM Error - Reallocating buffer size failed: %m.\n");
						exit(EXIT_FAILURE);
					}
					memcpy(attack_string + total_bytes - bytes_read, buffer, bytes_read);
					/* check if read limit was hit */
					if (read_limit) if (total_bytes < read_limit) continue;
				} else if (bytes_read == 0) 
					logmsg(LOG_NOISY, 1, "CSPM - Connectback session closed by foreign host.\n");
				else
					logmsg(LOG_WARN, 1, "CSPM - Could not read data from connectback session: %m.\n");


				/* process attack string */
				if (read_limit && total_bytes >= read_limit)
					logmsg(LOG_WARN, 1, "CSPM Warning - Read limit (%d bytes) hit. Closing connectback session.\n", read_limit);

				close(sockfd);
				// process data
				return(process_data(attack_string, total_bytes, NULL, 0, a->a_conn.l_port, a));
			}
		}
	}
	close(sockfd);


	return(1);
}
