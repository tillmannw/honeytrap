/* htprox.c
 * Copyright (C) 2007 Tillmann Werner <tillmann.werner@gmx.de>
 *
 * This file is free software; as a special exception the author gives
 * unlimited permission to copy and/or distribute it, with or without
 * modifications, as long as this notice is preserved.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
 * implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 *
 * This file is part of the honeytrap tools collection.
 *
 * htprox is a simple tcp proxy that accepts connections on a local port
 * and forward transmitted data to a remote host. When using the -b
 * option, responses are written to stdout.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>


void handle_signal(int sig) {
	fprintf(stdout, "Interrupted.\n");
	exit(0);
}


void usage(int exit_val) {
	FILE *out_file;

	out_file = ( exit_val > 0 ? stderr : stdout);

	fprintf(out_file, "Usage: htprox [ -bhv ] [ -p local_port ] [ remote_host remote_port ]\n");
	fprintf(out_file, "  -b:  write data from remote host in binary format to stdout\n");
	fprintf(out_file, "  -h:  print this output\n");
	fprintf(out_file, "  -p:  tcp port for data connections\n");
	fprintf(out_file, "  -v:  print version information\n");
	
	exit(exit_val);
}


int main(int argc, char *argv[]) {
	int			l_sockfd, r_sockfd, s_sockfd, sockopt, t, binmode,
				bytes_read, bytes_sent, total_bytes_sent;
	u_int16_t		r_port, s_port;
	fd_set			read_fds;
	struct timeval          st;
	struct sockaddr_in      r_sock, s_sock;
	struct hostent		*s_host;
	socklen_t               socklen;
	u_char			buffer[BUFSIZ];
	char			option;

	binmode			= 0;
	r_port			= 0;
	s_port			= 0;
	s_host			= NULL;
	l_sockfd		= -1;
	r_sockfd		= -1;
	s_sockfd		= -1;
	socklen			= sizeof(r_sock);

	bzero(&r_sock, sizeof(r_sock));
	bzero(&s_sock, sizeof(s_sock));


	/* signal stuff */
	if (signal(SIGINT, handle_signal) == SIG_ERR) {
		fprintf(stderr, "Could not install signal handler for SIGINT: %s.\n", strerror(errno));
		exit(1);
	}

	
	/* process args */
	while((option = getopt(argc, argv, "bvh?p:")) > 0) {
		switch(option) {
			case 'b':
				binmode = 1; 
				break;
			case 'p':
				if ((r_port = atoi(optarg)) == 0) {
					fprintf(stderr, "Error: -p takes a numeric value > 0.\n");
					exit(1);
				}
				break;
			case 'v':
				fprintf(stdout, "htprox v0.1 (c) Tillmann Werner\n");
				exit(0);
			case 'h':
			case '?':
				usage(0);
			default:
				break;
		}
	}
	if ((argc - optind) < 2) {
		fprintf(stderr, "Error: Need remote host/port.\n");
		usage(1);
	}
	if ((s_host = gethostbyname(argv[optind++])) == NULL) {
		fprintf(stderr, "Unable to resolve host: %s.\n", strerror(errno));
		usage(1);
	}
	if ((s_port = atoi(argv[optind++])) == 0) {
		fprintf(stderr, "Need a numeric value as port.\n");
		usage(1);
	}


	/* prepare connect socket */
	if ((s_sockfd = socket(PF_INET, SOCK_STREAM, 0)) == -1) {
		fprintf(stderr, "Could not create socket: %s.\n", strerror(errno));
		exit(1);
	}
	s_sock.sin_family	= AF_INET;
	s_sock.sin_addr.s_addr	= *((u_int32_t *)s_host->h_addr);
	s_sock.sin_port		= htons(s_port);
	if (connect(s_sockfd, (struct sockaddr *) &s_sock, sizeof(s_sock)) == -1) {
		fprintf(stderr, "Could not connect to %s:%d: %s.\n",
			inet_ntoa(*(struct in_addr*)s_host->h_addr), s_port, strerror(errno));
		exit(1);
	}
	if (binmode == 0) fprintf(stdout, "Connected to %s:%d.\n", inet_ntoa(*(struct in_addr*)s_host->h_addr), s_port);


	/* prepare listen socket */
	if ((l_sockfd = socket(PF_INET, SOCK_STREAM, 0)) == -1) {
		fprintf(stderr, "Could not create socket: %s.\n", strerror(errno));
		exit(1);
	}
	sockopt = 1;
	if (setsockopt(l_sockfd, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof(sockopt)) < 0)
		fprintf(stderr, "Warning - Unable to set SO_REUSEADDR on listening socket.\n");

	bzero(&r_sock, sizeof(r_sock));
	r_sock.sin_family	= AF_INET;
	r_sock.sin_addr.s_addr	= htonl(INADDR_ANY);
	r_sock.sin_port		= htons(r_port);
	if (bind(l_sockfd, (struct sockaddr *) &r_sock, sizeof(r_sock)) < 0) {
		fprintf(stderr, "Could not bind to port %d: %s.\n", r_port, strerror(errno));
		exit(1);
	}
	if (listen(l_sockfd, 0) < 0) {
		fprintf(stderr, "Could not start listening socket: %s.\n", strerror(errno));
		exit(1);
	}

	
	/* process data */
	for(;;) {
		FD_ZERO(&read_fds);
		FD_SET(l_sockfd, &read_fds);
		FD_SET(s_sockfd, &read_fds);
		if (r_sockfd > -1) FD_SET(r_sockfd, &read_fds);

		st.tv_sec  = 10;
		st.tv_usec = 0;

		switch (t = select(FD_SETSIZE, &read_fds, NULL, NULL, &st)) {
			case -1:
				fprintf(stderr, "Error with select(): %s.\n", strerror(errno));
				exit(1);
			case  0:
				break;
			default:
				if (FD_ISSET(l_sockfd, &read_fds)) {
					if ((r_sockfd = accept(l_sockfd, (struct sockaddr *) &s_sock, &socklen)) == -1) {
						fprintf(stderr, "Could not accept read connection: %s.\n", strerror(errno));
						exit(1);
					}
					total_bytes_sent = 0;
					break;
				}
				if (FD_ISSET(s_sockfd, &read_fds)) {
					if ((bytes_read = read(s_sockfd, buffer, BUFSIZ)) < 0) { 
						fprintf(stderr, "Error while reading data: %s.\n", strerror(errno));
						close(r_sockfd);
						close(s_sockfd);
						close(l_sockfd);
						exit(1);
					}
					if (bytes_read == 0) {
						if (binmode == 0) fprintf(stdout, "Connection closed by remote host.\n");
						close(r_sockfd);
						close(s_sockfd);
						close(l_sockfd);
						exit(0);
					}
					if ((bytes_sent = write(STDOUT_FILENO, buffer, bytes_read)) == -1) {
						fprintf(stderr, "Error while printing data: %s.\n", strerror(errno));
						close(r_sockfd);
						close(s_sockfd);
						close(l_sockfd);
						exit(1);
					}
					break;
				}
				if (FD_ISSET(r_sockfd, &read_fds)) {
					while ((bytes_read = read(r_sockfd, buffer, BUFSIZ)) > 0) {
						if ((bytes_sent = write(s_sockfd, buffer, bytes_read)) == -1) {
							fprintf(stderr, "Error while sending data: %s.\n", strerror(errno));
							close(r_sockfd);
							close(s_sockfd);
							close(l_sockfd);
							exit(1);
						}
						total_bytes_sent += bytes_sent;
					}
					if (bytes_read == 0) {
						if (binmode == 0) fprintf(stdout, "\t%u\t bytes sent to remote host.\n",
							total_bytes_sent);
						close(r_sockfd);
						r_sockfd = -1;
					} else if (bytes_read < 0) {
						fprintf(stderr, "Error while reading data: %s.\n", strerror(errno));
						close(r_sockfd);
						close(s_sockfd);
						close(l_sockfd);
						exit(1);
					}
					break;

				}
		}
	}
	return(0);	//never reached
}
