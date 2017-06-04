/* dynsrv.c
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

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "attack.h"
#include "ctrl.h"
#include "dynsrv.h"
#include "honeytrap.h"
#include "readconf.h"
#include "logging.h"
#include "response.h"
#include "md5.h"
#include "proxy.h"
#include "plughook.h"
#include "ipqmon.h"
#include "nfqmon.h"
#include "tcpip.h"
#include "sock.h"
#include "signals.h"


u_char          buffer[BUFSIZ], *attack_string;

int drop_privileges(void) {
	/* set gid first, it might not be permitted as unprivileged user */
	if (setgid(g_id) != 0) {
		logmsg(LOG_WARN, 1, "Warning - unable to set group id for server to %d.\n", g_id);
		return(0);
	}
	if (setuid(u_id) != 0) {
		logmsg(LOG_WARN, 1, "Warning - unable to set user id for server to %d.\n", u_id);
		return(0);
	}
	return(1);
}


void start_dynamic_server(struct in_addr ip_r, uint16_t port_r, struct in_addr ip_l, uint16_t port_l, uint16_t proto) {
	pid_t			pid;
	int			listen_fd, mirror_sock_fd, proxy_sock_fd, connection_fd,
				established;
#ifdef USE_IPQ_MON
	int			status;
#endif
	socklen_t		cliaddr_len, srvaddr_len;
	struct sockaddr_in	cliaddr, srvaddr;
	struct timeval		c_timeout;
	struct hostent		*proxy_addr;
	struct in_addr		*p_addr;
	proxy_dest		*proxy_dst;
	fd_set			rfds;
	char			*ip_l_str, *ip_r_str;
	Attack			*attack;
	u_char			port_mode;
	qelem			*elem;
	portinfo		*pinfo;

	proxy_addr	= NULL;
	proxy_dst	= NULL;
	attack_string	= NULL;
	ip_l_str	= NULL;
	ip_r_str	= NULL;
	attack		= NULL;
	listen_fd	= -1;
	connection_fd	= -1;
	mirror_sock_fd	= -1;
	proxy_sock_fd	= -1;
	established	= 0;
	port_mode	= portconf_default;

	if (!((proto == TCP) || (proto == UDP))) {
		logmsg(LOG_DEBUG, 1, "Unsupported protocol type.\n");
		return;
	}

	for (elem = portinfoq->head; elem; elem = elem->next) {
		pinfo = elem->data;
		if ((pinfo->port == port_l) && (pinfo->protocol == proto)) {
			if (pinfo->mode == PORTCONF_IGNORE) {
				qelem	*tmp = elem->prev;

				if (tmp) tmp->next	= elem->next;
				elem->prev		= tmp;

				free(elem->data);
				free(elem);
				
#ifdef USE_IPQ_MON
				/* hand packet processing back to the kernel */
				if ((status = ipq_set_verdict(h, packet->packet_id, NF_ACCEPT, 0, NULL)) < 0) {
					logmsg(LOG_ERR, 1, "Error - Could not set verdict on packet.\n");
					logmsg(LOG_ERR, 1, "IPQ Error: %s.\n", ipq_errstr());
					ipq_destroy_handle(h);
					exit(EXIT_FAILURE);
				}
				logmsg(LOG_DEBUG, 1, "IPQ - Successfully set verdict on packet.\n");
#endif
#ifdef USE_NFQ_MON
				/* hand packet processing back to the kernel
				 * nfq_set_verdict()'s return value is undocumented,
				 * but digging the source of libnetfilter_queue and libnfnetlink reveals
				 * that it's just the passed-through value of a sendmsg() */
				if (nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL) == -1) {
					logmsg(LOG_ERR, 1, "Error - Could not set verdict on packet: %m.\n");
					nfq_destroy_queue(qh);
					exit(EXIT_FAILURE);
				}
				logmsg(LOG_DEBUG, 1, "NFQ - Successfully set verdict on packet.\n");
#endif
				return;
			}
		}
	}

	logmsg(LOG_DEBUG, 1, "Calling plugins before dynamic server setup.\n");
	plughook_process_attack(funclist_attack_dynsrv, attack);

	/* fork server process */
	if ((pid = myfork()) == 0) {
		/* use this port string as log prefix */
		memset(portstr, 0, 16);
		if (snprintf(portstr, 16, "%5u/%s", ntohs(port_l), PROTO(proto)) > 15) {
			logmsg(LOG_ERR, 1, "Error - Port string is too long.\n");
			exit(EXIT_FAILURE);
		}

		if (proto == TCP) {
			logmsg(LOG_DEBUG, 1, "Requesting tcp socket.\n");
			if ((listen_fd = get_boundsock(&srvaddr, port_l, SOCK_STREAM)) == -1)
				exit(EXIT_SUCCESS);
		} else if (proto == UDP) {
			logmsg(LOG_DEBUG, 1, "Requesting udp socket.\n");
			if ((listen_fd = get_boundsock(&srvaddr, port_l, SOCK_DGRAM)) == -1)
				exit(EXIT_SUCCESS);
		}

#ifndef USE_IPQ_MON
#ifndef USE_NFQ_MON
		/* don't need root privs any more */
		drop_privileges();
		logmsg(LOG_DEBUG, 1, "Server is now running with user id %d and group id %d.\n", getuid(), getgid());
#endif
#endif

		/* create listener when handling tcp connection request */
		/* a backlog queue size of 10 should give us enough time to fork */
		if ((proto == TCP) && ((listen(listen_fd, 10)) < 0)) {
			logmsg(LOG_ERR, 1, "Error - Could not listen on socket: %m.\n");
			close(listen_fd);
			exit(EXIT_FAILURE);
		}
		logmsg(LOG_DEBUG, 1, "Listening on port %u/%s.\n", ntohs(port_l), PROTO(proto));

#ifdef USE_IPQ_MON
		/* hand packet processing back to the kernel */
		if ((status = ipq_set_verdict(h, packet->packet_id, NF_ACCEPT, 0, NULL)) < 0) {
			logmsg(LOG_ERR, 1, "Error - Could not set verdict on packet.\n");
			logmsg(LOG_ERR, 1, "IPQ Error: %s.\n", ipq_errstr());
			ipq_destroy_handle(h);
			exit(EXIT_FAILURE);
		}
		logmsg(LOG_DEBUG, 1, "IPQ - Successfully set verdict on packet.\n");

		/* don't need root privs any more */
		drop_privileges();
		logmsg(LOG_DEBUG, 1, "Server is now running with user id %d and group id %d.\n", getuid(), getgid());
#endif
#ifdef USE_NFQ_MON
		/* hand packet processing back to the kernel
		 * nfq_set_verdict()'s return value is undocumented,
		 * but digging the source of libnetfilter_queue and libnfnetlink reveals
		 * that it's just the passed-through value of a sendmsg() */
		if (nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL) == -1) {
			logmsg(LOG_ERR, 1, "Error - Could not set verdict on packet: %m.\n");
			nfq_destroy_queue(qh);
			exit(EXIT_FAILURE);
		}
		logmsg(LOG_DEBUG, 1, "NFQ - Successfully set verdict on packet.\n");

		/* don't need root privs any more */
		drop_privileges();
		logmsg(LOG_DEBUG, 1, "Server is now running with user id %d and group id %d.\n", geteuid(), getegid());
#endif

		/* wait for incoming connections */
		for (;;) {
			FD_ZERO(&rfds);
			FD_SET(sigpipe[0], &rfds);
			FD_SET(listen_fd, &rfds);

			c_timeout.tv_sec = conn_timeout;
			c_timeout.tv_usec = 0;

			switch (select(MAX(sigpipe[0], listen_fd) + 1, &rfds, NULL, NULL, &c_timeout)) {
			case -1:
				if (errno == EINTR) {
					if (check_sigpipe() == -1) exit(EXIT_FAILURE);
					break;
				}
				logmsg(LOG_ERR, 1, "   %s  Error - select() call failed: %m.\n", portstr);
				exit(EXIT_FAILURE);
			case 0:
				/* timeout */
				close(listen_fd);
				logmsg(LOG_NOISY, 1,
				       "-> %s  No incoming connection for %u seconds - server terminated.\n",
				       portstr, conn_timeout);
				exit(EXIT_SUCCESS);
			default:
				if (FD_ISSET(sigpipe[0], &rfds) && (check_sigpipe() == -1)) exit(EXIT_FAILURE);
				if (FD_ISSET(listen_fd, &rfds)) {


					/* accept connection depending on protocol */
					bzero(&cliaddr, sizeof(cliaddr));
					cliaddr_len = sizeof(cliaddr);
					established = 0;

					switch ((uint16_t) proto) {
					case TCP:
						/* accept tcp connection request */
						if ((connection_fd = accept(listen_fd, (struct sockaddr *)
									    &cliaddr, &cliaddr_len)) < 0) {
							if (errno == EINTR)
								break;
							else {
								logmsg(LOG_ERR, 1,
								       "   %s  Error - Could not accept tcp connection: %m.\n",
								       portstr);
								close(mirror_sock_fd);
								free(attack);
								exit(EXIT_FAILURE);
							}
						}

						// set keepalive option on connected socket
						int sockopt = 1;
						if (setsockopt(connection_fd, SOL_SOCKET, SO_KEEPALIVE, &sockopt, sizeof(sockopt)) < 0)
							logmsg(LOG_WARN, 1, "Warning - Unable to set SO_KEEPALIVE for socket.\n");

						established = 1;
						break;
					case UDP:
						connection_fd = dup(listen_fd);
						cliaddr.sin_family = AF_INET;
						cliaddr.sin_addr = ip_r;
						cliaddr.sin_port = port_r;

						/* connecting our udp socket enables us to use read() and write() */
						if (connect
						    (connection_fd, (struct sockaddr *) &cliaddr,
						     cliaddr_len) < 0) {
							if (errno == EINTR)
								break;
							else {
								logmsg(LOG_ERR, 1,
								       "   %s  Error - Could not connect udp socket: %m.\n",
								       portstr);
								close(mirror_sock_fd);
								free(attack);
								exit(EXIT_FAILURE);
							}
						}

						/* update remote endpoint information for attack structure */
						if (getpeername(connection_fd, (struct sockaddr *) &cliaddr,
						     &cliaddr_len) < 0) {
							if (errno == EINTR)
								break;
							else {
								logmsg(LOG_ERR, 1,
								       "   %s  Error - Could not get remote host information: %m.\n",
								       portstr);
								close(mirror_sock_fd);
								free(attack);
								exit(EXIT_FAILURE);
							}
						}
						established = 1;
						break;
					default:
						logmsg(LOG_ERR, 1, "Error - Protocol %d not supported.\n", proto);
						exit(EXIT_FAILURE);
					}
					if (!established) continue;
					

					/* get remote socket endpoint info */
					cliaddr_len = sizeof(cliaddr);
					if (getpeername(connection_fd, (struct sockaddr *) &cliaddr, (socklen_t *) &cliaddr_len) != 0) {
						logmsg(LOG_ERR, 1, "Error - Could not get client info from socket: %s.\n", strerror(errno));
						exit(1);
					}
					if ((ip_r_str = strdup(inet_ntoa(cliaddr.sin_addr))) == NULL) {
						logmsg(LOG_ERR, 1, "Error - Unable to allocate memory: %m.\n");
						exit(EXIT_FAILURE);
					}

					/* get local socket endpoint info */
					srvaddr_len = sizeof(srvaddr);
					if (getsockname(connection_fd, (struct sockaddr *) &srvaddr, (socklen_t *) &srvaddr_len) != 0) {
						logmsg(LOG_ERR, 1, "Error - Could not get client info from socket: %s.\n", strerror(errno));
						exit(1);
					}
					srvaddr.sin_addr = ip_l;
					if ((ip_l_str = strdup(inet_ntoa(srvaddr.sin_addr))) == NULL) {
						logmsg(LOG_ERR, 1, "Error - Unable to allocate memory: %m.\n");
						exit(EXIT_FAILURE);
					}

					logmsg(LOG_NOTICE, 1, "   %s  Handling %s connection request from %s:%d to %s:%d.\n",
						portstr, PROTO(proto), ip_r_str, ntohs(cliaddr.sin_port), ip_l_str, ntohs(srvaddr.sin_port));
					free(ip_r_str);
					free(ip_l_str);

					/* initialize attack record */
					if ((attack = new_attack(cliaddr.sin_addr, srvaddr.sin_addr, 0, ntohs(srvaddr.sin_port), proto)) == NULL) {
						logmsg(LOG_ERR, 1, "Error - Could not initialize attack record.\n");
						free(attack);
						exit(EXIT_FAILURE);
					}
					attack->a_conn.r_port = ntohs(cliaddr.sin_port);

					/* incoming connection accepted, select port mode */
					if (proto == TCP) {
						if (port_flags_tcp[htons(port_l)])
							port_mode = port_flags_tcp[htons(port_l)]->mode;
					} else if (proto == UDP) {
						if (port_flags_udp[htons(port_l)])
							port_mode = port_flags_udp[htons(port_l)]->mode;
					}

					attack->op_mode = port_mode;

					if (port_mode & PORTCONF_NORMAL) {
						/* handle connection in normal mode if this port configured to be handled 'normal' */
						logmsg(LOG_DEBUG, 1,
						       "   %s  Handling connection in normal mode.\n", portstr);
					} else if (port_mode & PORTCONF_PROXY) {
						/* get proxy server address for port */
						logmsg(LOG_DEBUG, 1,
						       "   %s  Handling connection in proxy mode.\n", portstr);

						if (proto == TCP) {
							if (port_flags_tcp[htons(port_l)])
								proxy_dst = port_flags_tcp[htons(port_l)]->target;
						} else if (proto == UDP) {
							if (port_flags_udp[htons(port_l)])
								proxy_dst = port_flags_udp[htons(port_l)]->target;
						}

						/* try to establish proxy connection to server */
						if ((proxy_addr = gethostbyname(proxy_dst->host)) == NULL) {
							logmsg(LOG_ERR, 1,
							       "   %s  Error - Unable to resolve proxy host %s.\n",
							       portstr, proxy_dst->host);
							free(attack);
							exit(EXIT_FAILURE);
						}
						logmsg(LOG_DEBUG, 1,
						       "== %s  Proxy hostname %s resolved to %s.\n",
						       portstr, proxy_dst->host,
						       inet_ntoa(*(struct in_addr *) proxy_addr->h_addr_list[0]));


						logmsg(LOG_DEBUG, 1,
						       "== %s  Requesting proxy connection to %s:%u.\n",
						       portstr, inet_ntoa(*(struct in_addr *) proxy_addr->h_addr_list[0]),
						       proxy_dst->port);
						p_addr = (struct in_addr *) proxy_addr->h_addr_list[0];
						if ((proxy_sock_fd =
						     proxy_connect(PORTCONF_PROXY, *p_addr,
								   ntohs(port_l), proxy_dst->port,
								   proto, attack)) == -1) {
							logmsg(LOG_INFO, 1,
							       "== %s  Proxy connection rejected, falling back to normal mode.\n",
							       portstr);
								port_mode = PORTCONF_NORMAL;
						} else
							logmsg(LOG_NOTICE, 1,
							       "== %s  Proxy connection to %s:%u established.\n",
							       portstr,
							       inet_ntoa(*(struct in_addr *) proxy_addr->
									 h_addr_list[0]), proxy_dst->port);
					} else if (port_mode & PORTCONF_MIRROR) {
						/* try to establish mirror connection back to the client */
						logmsg(LOG_DEBUG, 1,
						       "   %s  Handling connection in mirror mode.\n", portstr);

						logmsg(LOG_DEBUG, 1,
						       "<> %s  Requesting mirror connection to %s:%u.\n",
						       portstr, inet_ntoa(ip_r), ntohs(port_l));
						if ((mirror_sock_fd =
						     proxy_connect(PORTCONF_MIRROR,
								   (struct in_addr) ip_r,
								   ntohs(port_l), ntohs(port_l),
								   proto, attack)) == -1) {
							logmsg(LOG_INFO, 1,
							       "<> %s  Mirror connection rejected, falling back to normal mode.\n",
							       portstr);
								port_mode = PORTCONF_NORMAL;
						} else
							logmsg(LOG_NOTICE, 1,
							       "<> %s  Mirror connection to %s:%u established.\n",
							       portstr, inet_ntoa(ip_r), (uint16_t) ntohs(port_l));
					}


					/* fork connection handler */
					if ((pid = myfork()) == 0) {
						/* close listening socket in child */
						close(listen_fd);

						if (port_mode & PORTCONF_PROXY) {
							logmsg(LOG_DEBUG, 1,
							       "   %s  Handling connection from %s:%u in proxy mode.\n",
							       portstr,
							       inet_ntoa(cliaddr.sin_addr),
							       ntohs(cliaddr.sin_port));
							handle_connection_proxied(connection_fd,
										  PORTCONF_PROXY,
										  proxy_sock_fd, (uint16_t)
										  ntohs(port_l),
										  cliaddr.sin_port,
										  cliaddr.sin_addr,
										  proto,
										  m_read_timeout,
										  read_timeout, attack);
						} else if (port_mode & PORTCONF_MIRROR) {
							logmsg(LOG_DEBUG, 1,
							       "   %s  Handling connection from %s:%u in mirror mode.\n",
							       portstr,
							       inet_ntoa(cliaddr.sin_addr),
							       ntohs(cliaddr.sin_port));
							handle_connection_proxied(connection_fd,
										  PORTCONF_MIRROR,
										  mirror_sock_fd, (uint16_t)
										  ntohs(port_l),
										  cliaddr.sin_port,
										  cliaddr.sin_addr,
										  proto,
										  m_read_timeout,
										  read_timeout, attack);
						} else {
							logmsg(LOG_DEBUG, 1,
							       "   %s  Handling connection from %s:%u in normal mode.\n",
							       portstr,
							       inet_ntoa(cliaddr.sin_addr),
							       ntohs(cliaddr.sin_port));
							handle_connection_normal(connection_fd, (uint16_t)
										 ntohs(port_l), proto,
										 read_timeout, attack);
						}
						free(attack);
						exit(EXIT_SUCCESS);

					} else if (pid == -1)
						logmsg(LOG_ERR, 1, "Error - forking connection handler failed.\n");
					if (mirror_sock_fd >= 0) close(mirror_sock_fd);
					close(connection_fd);
					free(attack);
				} // FD_ISSET - incoming connection
			} // select return for listen_fd
		} // for - incoming connections
	} /* fork - server process */
	else if (pid == -1) logmsg(LOG_ERR, 1, "Error - Forking server process failed: %m.\n");
	return;
}


/* handle connection in normal mode - respond with default answers */
int handle_connection_normal(int connection_fd, uint16_t port, uint16_t proto, u_char timeout, Attack * attack) {
	fd_set		rfds;
	struct timeval	r_timeout;
	int		disconnect, bytes_read, total_bytes;

//#define total_bytes	attack->a_conn.payload.size
	total_bytes	= 0;
	disconnect	= 0;

	/* read data from sockets */
	for (;;) {
		FD_ZERO(&rfds);
		FD_SET(sigpipe[0], &rfds);
		FD_SET(connection_fd, &rfds);

		r_timeout.tv_sec = (u_char) timeout;
		r_timeout.tv_usec = 0;

		switch (select(MAX(connection_fd, sigpipe[0]) + 1, &rfds, NULL, NULL, &r_timeout)) {
		case -1:
			if (errno == EINTR) {
				if (check_sigpipe() == -1) exit(EXIT_FAILURE);
				break;
			}
			logmsg(LOG_ERR, 1, "   %s  Error - select() failed: %m.\n", portstr);
			close(connection_fd);
			return(process_data(attack_string, total_bytes, NULL, 0, attack->a_conn.l_port, attack));
		case 0:
			/* no data available, select() timed out */
			disconnect++;
			if (disconnect > 10) {
				/* close timeout'd connection and process attack string */
				logmsg(LOG_INFO, 1, "   %s  Timeout expired, closing connection.\n", portstr);
				close(connection_fd);
				return(process_data
					(attack_string, total_bytes, NULL, 0, attack->a_conn.l_port, attack));
			} else {
				if (send_default_response(connection_fd, port, proto, read_timeout) == -1) {
					logmsg(LOG_ERR, 1,
					       "   %s  Error - Sending response failed: %m.\n", portstr);
					close(connection_fd);
					return(process_data
						(attack_string, total_bytes, NULL, 0, attack->a_conn.l_port, attack));
				}
			}
			break;
		default:
			if (FD_ISSET(sigpipe[0], &rfds) && (check_sigpipe() == -1)) exit(EXIT_FAILURE);
			if (FD_ISSET(connection_fd, &rfds)) {
				/* handle data on server connection */
				if ((bytes_read = read(connection_fd, buffer, sizeof(buffer))) > 0) {
					logmsg(LOG_INFO, 1, "   %s* %d bytes read.\n", portstr, bytes_read);
					total_bytes += bytes_read;
					if (!(attack_string = (u_char *) realloc(attack_string, total_bytes))) {
						logmsg(LOG_ERR, 1,
						       "   %s  Error - Reallocating buffer size failed: %m.\n", portstr);
						free(attack_string);
						exit(EXIT_FAILURE);
					}
					memcpy(attack_string + total_bytes - bytes_read, buffer, bytes_read);
					disconnect = 0;
					/* check if read limit was hit */
					if (read_limit) if (total_bytes >= read_limit) {
						/* read limit hit, process attack string */
						logmsg(LOG_WARN, 1,
						       "   %s  Warning - Read limit (%d bytes) hit. Closing connection.\n",
						       portstr, read_limit);
						close(connection_fd);
						return(process_data
							(attack_string, total_bytes, NULL, 0, attack->a_conn.l_port, attack));
					}
					logmsg(LOG_DEBUG, 1, "Calling plugins for hook 'process_attack'.\n");
					attack->a_conn.payload.size = total_bytes;
					attack->a_conn.payload.data = attack_string;
					plughook_process_attack(funclist_attack_perread, attack);
				} else if (bytes_read == 0) {
					shutdown(connection_fd, SHUT_RDWR);
					logmsg(LOG_INFO, 1, "   %s  Connection closed by foreign host.\n", portstr);

					/* process attack string */
					return(process_data
						(attack_string, total_bytes, NULL, 0, attack->a_conn.l_port, attack));
				} else {
					logmsg(LOG_NOISY, 1, "   %s  Could not read data: %m.\n", portstr);
					close(connection_fd);
					return(process_data
						(attack_string, total_bytes, NULL, 0, attack->a_conn.l_port, attack));
				}
			} // FD_ISSET
		} // switch
	} // for
}


/* handle connection in proxy or mirror mode
 * - in proxy mode connections are proxied to configured hosts 
 * - in mirror mode all data mirrored from the connecting client back to itself and vice versa */
int handle_connection_proxied(int connection_fd, u_char mode, int server_sock_fd, uint16_t dport, uint16_t sport,
			  struct in_addr ipaddr, uint16_t proto, u_char timeout, u_char fb_timeout, Attack * attack) {
	fd_set		rfds;
	struct timeval	r_timeout;
	int		bytes_read, bytes_sent, total_bytes, total_from_server, rv;
	u_char		*server_string;
	char		*logstr, *Logstr, *logact, *logpre;

	bytes_read		= 0;
	bytes_sent		= 0;
	total_bytes		= 0;
	total_from_server	= 0;
	server_string		= NULL;

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
		logmsg(LOG_ERR, 1, "Error - Mode %u for connection handling is not supported.\n", mode);
		exit(EXIT_FAILURE);
	}

	/* read data from sockets */
	for (;;) {
		FD_ZERO(&rfds);
		FD_SET(connection_fd, &rfds);
		FD_SET(server_sock_fd, &rfds);

		r_timeout.tv_sec = (u_char) timeout;
		r_timeout.tv_usec = 0;
		switch (select(MAX(MAX(server_sock_fd, connection_fd), sigpipe[0]) + 1, &rfds, NULL, NULL, &r_timeout)) {
		case -1:
			if (errno == EINTR) {
				if (check_sigpipe() == -1) exit(EXIT_FAILURE);
				break;
			}
			logmsg(LOG_INFO, 1, "%s %s  Error - Select failed: %m.\n", logpre, portstr);
			shutdown(server_sock_fd, SHUT_RDWR);
			shutdown(connection_fd, SHUT_RDWR);
			return(process_data
				(attack_string, total_bytes, server_string, total_from_server, dport, attack));
		case 0:
			/* select() timed out, close connections */
			logmsg(LOG_INFO, 1,
			       "%s %s  %s connection timed out, closing connections.\n", logpre, portstr, Logstr);
			shutdown(server_sock_fd, SHUT_RDWR);
			shutdown(connection_fd, SHUT_RDWR);
			return(process_data
				(attack_string, total_bytes, server_string, total_from_server, dport, attack));
		default:
			if (FD_ISSET(sigpipe[0], &rfds) && (check_sigpipe() == -1)) exit(EXIT_FAILURE);
			if (FD_ISSET(server_sock_fd, &rfds)) {
				/* read data and proxy it to client connection */
				bytes_read = 0;
				if ((rv = copy_data(connection_fd, server_sock_fd, &server_string,
					       total_from_server, &bytes_read, &bytes_sent)) > 0) {
					logmsg(LOG_INFO, 1,
					       "%s %s* %u (of %u) bytes copied from %s connection to %s:%u.\n",
					       logpre, portstr, bytes_sent, bytes_read, logact, inet_ntoa(ipaddr), sport);
					total_from_server += bytes_read;
					if (read_limit) if (total_from_server >= read_limit) {
						/* read limit hit, process attack string */
						logmsg(LOG_WARN, 1,
						       "%s %s  Warning - Read limit (%u bytes) hit. Closing %s connections.\n",
						       logpre, portstr, read_limit, logact);
						shutdown(server_sock_fd, SHUT_RDWR);
						shutdown(connection_fd, SHUT_RDWR);
						return(process_data
							(attack_string, total_bytes, server_string,
							 total_from_server, dport, attack));
					}
					logmsg(LOG_DEBUG, 1, "Calling plugins for hook 'process_attack'.\n");
					attack->a_conn.payload.size = total_bytes;
					attack->a_conn.payload.data = attack_string;
					plughook_process_attack(funclist_attack_perread, attack);
				} else if (rv == 0) {
					/* first UDP packet was rejected, fall back to normal mode */
					if ((proto == UDP) && (total_bytes == bytes_sent))
						return(handle_connection_normal
							(connection_fd, dport, proto, read_timeout, attack));

					/* remote host closed server connection */
					logmsg(LOG_INFO, 1,
					       "%s %s  %s connection closed by foreign host.\n", logpre, portstr, Logstr);
					shutdown(server_sock_fd, SHUT_RDWR);
					shutdown(connection_fd, SHUT_RDWR);
					return(process_data
						(attack_string, total_bytes, server_string, total_from_server, dport, attack));
				} else {
					/* copy_data error */
					logmsg(LOG_INFO, 1,
					       "%s %s  Error - Unable to %s data to client connection.\n",
					       logpre, portstr, logact);
					if (close(server_sock_fd) == -1)
						logmsg(LOG_ERR, 1,
						       "%s %s  Error - Unable to close %s sockt.\n", logpre, portstr, logstr);
					else
						logmsg(LOG_NOISY, 1, "%s %s  %s connection closed.\n", logpre, portstr, Logstr);
					shutdown(connection_fd, SHUT_RDWR);
					return(process_data
						(attack_string, total_bytes, server_string, total_from_server, dport, attack));
				}
			}
			if (FD_ISSET(connection_fd, &rfds)) {
				/* read data and proxy it to server connection */
				bytes_read = 0;
				if ((rv = copy_data(server_sock_fd, connection_fd, &attack_string,
					       total_bytes, &bytes_read, &bytes_sent)) > 0) {
					logmsg(LOG_INFO, 1,
					       "%s %s* %u (of %u) bytes copied from client connection to %s:%u.\n",
					       logpre, portstr, bytes_sent, bytes_read, inet_ntoa(ipaddr), dport);
					total_bytes += bytes_read;
					if (read_limit) if (total_from_server >= read_limit) {
						/* read limit hit, process attack string */
						logmsg(LOG_WARN, 1,
						       "%s %s  Warning - Read limit (%u bytes) hit. Closing %s connections.\n",
						       logpre, portstr, read_limit, logact);
						shutdown(server_sock_fd, SHUT_RDWR);
						shutdown(connection_fd, SHUT_RDWR);
						return(process_data
							(attack_string, total_bytes, server_string,
							 total_from_server, dport, attack));
					}
				} else if (rv == 0) {
					/* remote host closed client connection */
					shutdown(server_sock_fd, SHUT_RDWR);
					logmsg(LOG_INFO, 1, "%s %s  Connection closed by foreign host.\n", logpre, portstr);
					shutdown(server_sock_fd, SHUT_RDWR);
					logmsg(LOG_NOISY, 1, "%s %s  %s connection closed.\n", logpre, portstr, Logstr);
					return(process_data
						(attack_string, total_bytes, server_string, total_from_server, dport, attack));
				} else {
					/* copy_data error */
					logmsg(LOG_INFO, 1,
					       "%s %s  Error - Unable to %s data to %s connection.\n",
					       logpre, portstr, logact, logstr);
					shutdown(server_sock_fd, SHUT_RDWR);
					shutdown(connection_fd, SHUT_RDWR);
					return(process_data
						(attack_string, total_bytes, server_string, total_from_server, dport, attack));
				}
			}
		} // switch
	}
	return(0);	// never reached
}

int check_portinfopipe(void) {
	int		rv;
	portinfo	*pinfo;
	qelem		*elem;

	if ((pinfo = calloc(1, sizeof(portinfo))) == NULL) {
		logmsg(LOG_ERR, 1, "Error - Unable to allocate memory: %s.\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	switch(rv = read(portinfopipe[0], pinfo, sizeof(portinfo))) {
	case sizeof(portinfo):
		logmsg(LOG_INFO, 1, "Portinfo received - port %u, mode %d\n", ntohs(pinfo->port), pinfo->mode);
		if ((elem = queue_append(portinfoq, &pinfo)) == NULL)
			logmsg(LOG_WARN, 1, "Warning - Unable to register port information.\n");
		pinfo = elem->data;
		break;
	case 0:
		logmsg(LOG_WARN, 1, "Warning - IPC pipe ready to read but not enough data available.\n");
		break;
	case -1:
		logmsg(LOG_ERR, 1, "Error - Unable to read from pipe: %s.\n", strerror(errno));
		break;
	}
	return rv;
}
