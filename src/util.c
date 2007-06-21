/* util.c
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

#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "honeytrap.h"
#include "util.h"
#include "signals.h"
#include "logging.h"

int valid_ipaddr(uint32_t address) {
	/* check if 'address' is an ip address with a reasonable value */
	/* realized as function to be able to add additional checks, i.e. exclude rfc1918 addresses */
	return(address > 0 ? 1 : 0);
}

int read_line(int socket, char *line, ssize_t len, int timeout) {
	/* reads a line from 'socket' into buffer 'line' */
	/* 'timeout' is optional, 0 means read without timeout */

	int		read_chars = 0;
	int		rv = 0;
	fd_set		rfds;
	struct timeval	r_timeout;

	memset(line, 0, len);

	/* read line with timeout */
	if (timeout) {
		FD_ZERO(&rfds);
		FD_SET(socket, &rfds);
		FD_SET(sigpipe[0], &rfds);
		r_timeout.tv_sec = timeout;
		r_timeout.tv_usec = 0;

		/* wait for incoming data, close connection on timeout */
		logmsg(LOG_DEBUG, 1, "Trying to read a line from socket, timeout is %d seconds.\n",
			(uint16_t) r_timeout.tv_sec);
		
		for (;;) {
			switch (select(MAX(sigpipe[0], socket) + 1, &rfds, NULL, NULL, &r_timeout)) {
			case -1:
				if (errno == EINTR) {
					if (check_sigpipe() == -1) exit(EXIT_FAILURE);
					break;
				}
				logmsg(LOG_DEBUG, 1, "Error while reading a line from socket - select() failed.\n");
				return(-1);
			case 0:
				logmsg(LOG_DEBUG, 1, "Error while reading a line from socket - Connection timed out.\n");
				return(-1);
			default:
				if (FD_ISSET(sigpipe[0], &rfds) && (check_sigpipe() == -1))
					exit(EXIT_FAILURE);
				if (FD_ISSET(socket, &rfds)) {
					if (read_chars >= len-1) {
						logmsg(LOG_DEBUG, 1, "Error while reading from socket - Line exceeds buffer.\n");
						return(-2);
					}
					rv = recv(socket, &line[read_chars], 1, 0);
					if (rv == 0) return(read_chars);
					if (rv < 0) return(-1);
					if (line[read_chars] == '\n') {
						line[read_chars] = '\0';
						logmsg(LOG_DEBUG, 1, "Line read: %s\n", line);
						return(read_chars);
					}
					read_chars++;
				}
			}
		}
	}

	/* read line without timeout */
	while (1){
		if (read_chars >= len-1) {
			logmsg(LOG_DEBUG, 1, "Error while reading from socket - Line exceeds buffer.\n");
			return(-2);
		}
		rv = recv(socket, &line[read_chars], 1, 0);
		if (rv == 0) return(read_chars);
		if (rv < 0) return(-1);
		if (line[read_chars] == '\n') {
			line[read_chars] = '\0';
			return(read_chars);
		}
		read_chars++;
	}
	return(0);
}


struct strtk extract_token(char *parse_string) {
	/* returns substring (string until next occurrence of '>', '&' or '\n' and its offset in a struct */
	/* used to extract tokens from shell commands */
	int length;
	struct strtk rv;

	rv.string	= parse_string;
	rv.offset	= 0;
	
	length = strlen(parse_string);

	while(isspace(*parse_string)) {
		rv.string++;
		rv.offset++;
		parse_string++;
	}

	while (	(rv.offset < length) &&
		(!isspace(*parse_string)) &&
		(*parse_string != '>') &&
		(*parse_string != '&') &&
		(*parse_string != '\n')) {
		rv.offset++;
		parse_string++;
	}
	*parse_string = 0;
	rv.offset++;

	return(rv);
}


char *get_next_line(FILE * file) {
	/* return next line from file */

	char buf[BUFSIZ];
	char *index;

	bzero((char *)buf, BUFSIZ);

	while(fgets(buf, BUFSIZ, file)) {
		index = buf;
		/* advance through whitespaces at the beginning of the line */
		while (isspace((int) *index)) ++index;

		return((char *) strdup(index));
	}
	return(NULL);
}


