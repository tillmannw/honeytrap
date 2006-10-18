/* dynsrv.c
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
#include "dynsrv.h"
#include "response.h"
#include "md5.h"
#include "proxy.h"
#include "plughook.h"
#include "ipqmon.h"
#include "tcp.h"
#include "udp.h"
#include "attack.h"

u_char buffer[BUFSIZ], *attack_string;

int drop_privileges(void) {
	/* set gid first, it might not be permitted as unprivileged user */
	if(setgid(g_id) != 0) {
		logmsg(LOG_WARN, 1, "Warning - unable to set group id for server to %d.\n", g_id);
		return(1);
	}
	if(setuid(u_id) != 0) {
		logmsg(LOG_WARN, 1, "Warning - unable to set user id for server to %d.\n", u_id);
		return(1);
	}
	return(0);
}


void start_dynamic_server(struct in_addr ip_r, uint16_t port_r, struct in_addr ip_l, uint16_t port_l, uint16_t proto) {
    pid_t pid;
    int listen_fd, mirror_sock_fd, proxy_sock_fd, connection_fd, disconnect,
	total_bytes, select_return, mirror_this, proxy_this, established;
    socklen_t client_addr_len;
    struct sockaddr_in client_addr, server_addr;
    struct timeval c_timeout;
    struct s_proxy_dest *proxy_dst;
    struct hostent *proxy_addr;
    struct in_addr *p_addr;
    fd_set rfds;
    char *ip_l_str, *ip_r_str;
    Attack *attack;

    proxy_addr		= NULL;
    proxy_dst		= NULL;
    attack_string	= NULL;
    ip_l_str		= NULL;
    ip_r_str		= NULL;
    attack		= NULL;
    select_return	= -1;
    listen_fd		= -1;
    connection_fd	= -1;
    mirror_sock_fd	= -1;
    proxy_sock_fd	= -1;
    proxy_this		= 0;
    mirror_this		= 1;
    established		= 0;

    if (!((proto == TCP) || (proto == UDP))) {
	logmsg(LOG_DEBUG, 1, "Unsupported protocol type.\n");
	exit(0);
    }

    logmsg(LOG_DEBUG, 1, "-> %u\t  Connection request from %s, forking server process.\n",
	    (uint16_t) ntohs(port_l), inet_ntoa(ip_r));

    /* fork server process */
    if ((pid = fork()) == 0) {
	    ip_l_str = strdup(inet_ntoa(ip_l));
	    ip_r_str = strdup(inet_ntoa(ip_r));

	if (proto == TCP) {
		logmsg(LOG_DEBUG, 1, "Requesting tcp socket.\n");
		if ((listen_fd = tcpsock(&server_addr, port_l)) < 0) exit(1);
	} else if (proto == UDP) {
		logmsg(LOG_DEBUG, 1, "Requesting udp socket.\n");
		if ((listen_fd = udpsock(&server_addr, port_l)) < 0) exit(1);
	} else {
		logmsg(LOG_DEBUG, 1, "Unsupported protocol type.\n");
		exit(0);
	}

	/* don't need root privs any more */
	drop_privileges(); 
	logmsg(LOG_DEBUG, 1, "Server is now running with user id %d and group id %d.\n", getuid(), getgid());

	/* create listener when handling tcp connection request */
	/* a backlog queue size of 10 should give us enough time to fork */
	if ((proto == TCP) && ((listen(listen_fd, 10)) < 0)) {
	    logmsg(LOG_ERR, 1, "Error - Could not listen on socket: %s.\n", strerror(errno));
	    close(listen_fd);
	    exit(1);
	}
	logmsg(LOG_DEBUG, 1, "Listening on port %u/%s.\n", ntohs(port_l), PROTO(proto));

		  
	/* wait for incoming connections */
	for (;;) {
	    FD_ZERO(&rfds);
	    FD_SET(listen_fd, &rfds);

	    c_timeout.tv_sec = conn_timeout;
	    c_timeout.tv_usec = 0;

	    switch (select_return = select(listen_fd + 1, &rfds, NULL, NULL, &c_timeout)) {
	    case -1:
		if (errno == EINTR) break;
		logmsg(LOG_ERR, 1, "   %u\t  Error - select() call failed: %s.\n",
		    (uint16_t) ntohs(port_l), strerror(errno));
		exit(1);
	    case  0:
		/* timeout */
		logmsg(LOG_NOISY, 1, "-> %u\t  No incoming connection for %u seconds - server terminated.\n",
		    (uint16_t) ntohs(port_l), conn_timeout);
		exit(0);
	    default:
		if (FD_ISSET(listen_fd, &rfds)) {
		    logmsg(LOG_NOISY, 1, "   %u\t  Connection request from %s.\n",
			(uint16_t) ntohs(port_l), inet_ntoa(ip_r));

		    /* initialize attack record */
		    if ((attack = new_attack(ip_l, ip_r, ntohs(port_l), 0)) == NULL) {
			logmsg(LOG_ERR, 1, "Error - Could not initialize attack record.\n");
			free(attack);
			exit(1);
		    }

		    if (port_flags[ntohs(port_l)] & PORTCONF_NORMAL) {
		    	/* handle connection in normal mode if this port configured to be handled 'normal' */
			logmsg(LOG_DEBUG, 1, "   %u\t  Handling connection in normal mode.\n", (uint16_t) ntohs(port_l));
			mirror_this = 0;
			proxy_this = 0;
		    } else if (port_flags[ntohs(port_l)] & PORTCONF_PROXY) {
			/* get proxy server for port */
			logmsg(LOG_DEBUG, 1, "   %u\t  Handling connection in proxy mode.\n", (uint16_t) ntohs(port_l));
			proxy_dst = proxy_dest;
			while (proxy_dst) {
			    if (proxy_dst->attack_port == ntohs(port_l)) break;
			    proxy_dst = proxy_dst->next;
			}
			if (proxy_dst->attack_port == ntohs(port_l)) {
				/* try establish proxy connection to server */
                            if ((proxy_addr = gethostbyname(proxy_dst->d_addr)) == NULL) {
                                logmsg(LOG_ERR, 1, "   %u\t  Error - Unable to resolve proxy host %s.\n",
				    (uint16_t) ntohs(port_l), proxy_dst->d_addr);
				free(attack);
                                exit(0);
                            }
                            logmsg(LOG_DEBUG, 1, "== %u\t  Proxy hostname %s resolved to %s.\n",
                                (uint16_t) ntohs(port_l), proxy_dst->d_addr,
                                inet_ntoa(*(struct in_addr*)proxy_addr->h_addr_list[0]));


			    logmsg(LOG_DEBUG, 1, "== %u\t  Requesting proxy connection to %s:%u.\n",
				(uint16_t) ntohs(port_l),
				inet_ntoa(*(struct in_addr*)proxy_addr->h_addr_list[0]), proxy_dst->d_port);
			    p_addr = (struct in_addr *) proxy_addr->h_addr_list[0];
			    if ((proxy_sock_fd = proxy_connect(PORTCONF_PROXY, *p_addr,
				ntohs(port_l), proxy_dst->d_port, attack)) == -1) {
				logmsg(LOG_INFO, 1, "== %u\t  Proxy connection rejected, falling back to normal mode.\n",
				    (uint16_t) ntohs(port_l));
				proxy_this = 0;
			    } else logmsg(LOG_NOTICE, 1, "== %u\t  Proxy connection to %s:%u established.\n",
				(uint16_t) ntohs(port_l),
				inet_ntoa(*(struct in_addr*)proxy_addr->h_addr_list[0]), proxy_dst->d_port);
			}
		    } else if ((mirror_this) || (port_flags[ntohs(port_l)] & PORTCONF_MIRROR)) {
			/* try to establish mirror connection back to the client */
			logmsg(LOG_DEBUG, 1, "   %u\t  Handling connection in mirror mode.\n", (uint16_t) ntohs(port_l));

			logmsg(LOG_DEBUG, 1, "<> %u\t  Requesting mirror connection to %s:%u.\n",
			    (uint16_t) ntohs(port_l), inet_ntoa(ip_r), ntohs(port_l));
			if ((mirror_sock_fd = proxy_connect(PORTCONF_MIRROR,
			    (struct in_addr) ip_r, ntohs(port_l), ntohs(port_l), attack)) == -1) {
			    logmsg(LOG_INFO, 1, "<> %u\t  Mirror connection rejected, falling back to normal mode.\n",
				(uint16_t) ntohs(port_l));
			    mirror_this = 0;
			} else logmsg(LOG_NOTICE, 1, "<> %u\t  Mirror connection to %s:%u established.\n",
			    (uint16_t) ntohs(port_l), inet_ntoa(ip_r), (uint16_t) ntohs(port_l));
		    }

		    bzero(&client_addr, sizeof(client_addr));
		    client_addr_len	= sizeof(client_addr);
		    established		= 0;


		    /* accept connection depending on protocol */
		    switch ((uint16_t)proto) {
			case TCP:
			    /* accept tcp connection request */
			    if ((connection_fd = accept(listen_fd,
				(struct sockaddr *) &client_addr, &client_addr_len)) < 0) {
				if (errno == EINTR) break;
				else {
				    logmsg(LOG_ERR, 1, "   %u\t  Error - Could not accept tcp connection: %s\n",
					(uint16_t) ntohs(port_l), strerror(errno));
				    close(mirror_sock_fd);
				    free(attack);
				    exit(1);
				}
			    }
			    established = 1;
			    break;
			case UDP:
			    connection_fd		= dup(listen_fd);
			    client_addr.sin_family	= AF_INET;
			    client_addr.sin_addr	= ip_r;
			    client_addr.sin_port	= port_r;

			    /* connecting our udp socket enables us to use read() and write() */
			    if (connect(connection_fd, (struct sockaddr *) &client_addr, client_addr_len) < 0) {
				if (errno == EINTR) break;
				else {
				    logmsg(LOG_ERR, 1, "   %u\t  Error - Could not connect udp socket: %s\n",
					(uint16_t) ntohs(port_l), strerror(errno));
				    close(mirror_sock_fd);
				    free(attack);
				    exit(1);
				}
			    }

			    /* update remote endpoint information for attack structure */
			    if (getpeername(connection_fd, (struct sockaddr *) &client_addr, &client_addr_len) < 0) {
				if (errno == EINTR) break;
				else {
				    logmsg(LOG_ERR, 1, "   %u\t  Error - Could not get remote host information: %s\n",
					(uint16_t) ntohs(port_l), strerror(errno));
				    close(mirror_sock_fd);
				    free(attack);
				    exit(1);
				}
			    }
			    established = 1;
			    break;
			default:
			    return;
		    }


		    if (established) {
			/* connection successful established, fork handler process */
					
			logmsg(LOG_NOTICE, 1, "   %u\t  Connection from %s:%u established.\n",
				(uint16_t) ntohs(port_l), inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
			attack->a_conn.r_port	= ntohs(client_addr.sin_port);
			
			if ((pid = fork()) == 0) {
			    /* close listening socket in child */
			    close(listen_fd);
			    disconnect		= 0;
			    total_bytes		= 0;

			    if ((proxy_this) || (port_flags[ntohs(port_l)] & PORTCONF_PROXY)) {
				logmsg(LOG_DEBUG, 1, "   %u\t  Handling connection from %s:%u in proxy mode.\n",
				    (uint16_t) ntohs(port_l), inet_ntoa(client_addr.sin_addr),
				    ntohs(client_addr.sin_port));
				handle_connection_proxied(connection_fd, PORTCONF_PROXY, proxy_sock_fd,
				    (uint16_t) ntohs(port_l), client_addr.sin_port,
				    client_addr.sin_addr, m_read_timeout, read_timeout, attack);
				free(attack);
				exit(0);
			    } else if ((mirror_this) || (port_flags[ntohs(client_addr.sin_port)] & PORTCONF_MIRROR)) {
				logmsg(LOG_DEBUG, 1, "   %u\t  Handling connection from %s:%u in mirror mode.\n",
				    (uint16_t) ntohs(port_l), inet_ntoa(client_addr.sin_addr),
				    ntohs(client_addr.sin_port));
				handle_connection_proxied(connection_fd, PORTCONF_MIRROR, mirror_sock_fd,
				    (uint16_t) ntohs(port_l), client_addr.sin_port,
				    client_addr.sin_addr, m_read_timeout, read_timeout, attack);
				free(attack);
				exit(0);
			    } else {
				logmsg(LOG_DEBUG, 1, "   %u\t  Handling connection from %s:%u in normal mode.\n",
				    (uint16_t) ntohs(port_l), inet_ntoa(client_addr.sin_addr),
				    ntohs(client_addr.sin_port));
				handle_connection_normal(connection_fd, (uint16_t) ntohs(port_l), read_timeout, attack);
				free(attack);
				exit(0);
			    }

			} else if (pid == -1) logmsg(LOG_ERR, 1, "Error - forking connection handler failed.\n");
			close(mirror_sock_fd);
			close(connection_fd);
			free(attack);
		    } /* connection accepted */
		} /* FD_ISSET - incoming connection */
	    } /* select return for listen_fd */	
	} /* for - incoming connections */
    } /* fork - server process */
    else if (pid == -1) logmsg(LOG_ERR, 1, "Error - forking server process failed.\n");
    return;
}


/* handle connection in normal mode - respond with default answers */
int handle_connection_normal(int connection_fd, uint16_t port, u_char timeout, Attack *attack) {
    fd_set rfds;
    struct timeval r_timeout;
    int disconnect, bytes_read, total_bytes, retval;
	    
    total_bytes	= 0;
    disconnect	= 0;

    /* read data from sockets */
    for (;;) {
	FD_ZERO(&rfds);
	FD_SET(connection_fd, &rfds);

	r_timeout.tv_sec = (u_char) timeout;
	r_timeout.tv_usec = 0;

	if (((retval = select(connection_fd + 1, &rfds, NULL, NULL, &r_timeout)) < 0) && (errno != EINTR)) {
	    logmsg(LOG_ERR, 1, "   %u\t  Error - select() failed: %s.\n", port, strerror(errno));
	    close(connection_fd);
	    return(process_data(attack_string, total_bytes, NULL, 0, attack->a_conn.l_port, attack));
	} else if (retval == 0) {
	    /* no data available, select() timed out */
	    disconnect++;
	    if (disconnect > 10) {
		/* close timeout'd connection and process attack string */
		logmsg(LOG_INFO, 1, "   %u\t  Timeout expired, closing connection.\n", port);
		close(connection_fd);
		return(process_data(attack_string, total_bytes, NULL, 0, attack->a_conn.l_port, attack));
	    } else {
		if ((!send_default_response(connection_fd, port, read_timeout)) == -1) {
		    logmsg(LOG_ERR, 1, "   %u\t  Error - Sending response failed: %s.\n", port, strerror(errno));
		    close(connection_fd);
		    return(process_data(attack_string, total_bytes, NULL, 0, attack->a_conn.l_port, attack));
		}
	    }
	}

	/* handle data on server connection */
	if (FD_ISSET(connection_fd, &rfds)) {
	    if ((bytes_read = read(connection_fd, buffer, sizeof(buffer))) > 0) {
		logmsg(LOG_INFO, 1, "   %u\t* %d bytes read.\n", port, bytes_read);
		total_bytes += bytes_read;
		if (!(attack_string = (u_char *) realloc(attack_string, total_bytes))) {
		    logmsg(LOG_ERR, 1, "   %u\t  Error - Reallocating buffer size failed: %s.\n", port, strerror(errno));
		    free(attack_string);
		    return(-1);
		}
		memcpy(attack_string + total_bytes - bytes_read, buffer, bytes_read);
    		disconnect = 0;
		/* check if read limit was hit */
		if (bytes_read >= read_limit) {
			/* read limit hit, process attack string */
			logmsg(LOG_WARN, 1, "   %u\t  Warning - Byte limit (%d) hit. Closing connection.\n",
				port, read_limit);
			close(connection_fd);
			return(process_data(attack_string, total_bytes, NULL, 0, attack->a_conn.l_port, attack));
		}
	    } else if (bytes_read == 0) {
		logmsg(LOG_INFO, 1, "   %u\t  Connection closed by foreign host.\n", port);

		/* process attack string */
		close(connection_fd);
		return(process_data(attack_string, total_bytes, NULL, 0, attack->a_conn.l_port, attack));
	    } else {
		logmsg(LOG_ERR, 1, "   %u\t  Error - Could not read data: %s.\n", port, strerror(errno));
		close(connection_fd);
		return(process_data(attack_string, total_bytes, NULL, 0, attack->a_conn.l_port, attack));
	    }
	} /* FD_ISSER(connection_fd) */
    } /* for */
}


/* handle connection in proxy or mirror mode
 * - in proxy mode connections are proxied to configured hosts 
 * - in mirror mode all data mirrored from the connecting client back to itself and vice versa */
int handle_connection_proxied(int connection_fd, u_char mode, int server_sock_fd, uint16_t dport, uint16_t sport, struct in_addr ipaddr, u_char timeout, u_char fb_timeout, Attack *attack) {
    fd_set rfds;
    struct timeval r_timeout;
    int disconnect, bytes_read, bytes_sent, total_bytes, total_from_server, retval, max_read_fd;
    u_char *server_string;
    char *logstr, *Logstr, *logact, *logpre;

    disconnect	= 0;
    total_bytes	= 0;
    total_from_server = 0;
    server_string = NULL;

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
	return(-1);
    }

    /* read data from sockets */
    for (;;) {
	FD_ZERO(&rfds);
	FD_SET(connection_fd, &rfds);
	FD_SET(server_sock_fd, &rfds);

	max_read_fd = server_sock_fd > connection_fd ? server_sock_fd : connection_fd;

	r_timeout.tv_sec = (u_char) timeout;
	r_timeout.tv_usec = 0;
	if ((select(max_read_fd + 1, &rfds, NULL, NULL, &r_timeout) < 0) && (errno != EINTR)) {
	    logmsg(LOG_INFO, 1, "%s %u\t  Error - Select failed: %s.\n", logpre, dport, strerror(errno));
	    close(server_sock_fd);
	    close(connection_fd);
	    return(process_data(attack_string, total_bytes, server_string, total_from_server, dport, attack));
	}

	if (FD_ISSET(server_sock_fd, &rfds)) {
	/* read data and proxy it to client connection */
	    bytes_read = 0;
	    if ((retval =
		tcpcopy(connection_fd, server_sock_fd, &server_string, total_from_server, &bytes_read, &bytes_sent)) > 0) {
		logmsg(LOG_INFO, 1, "%s %u\t* %u (of %u) bytes copied from %s connection to %s:%u.\n",
			logpre, dport, bytes_sent, bytes_read, logact, inet_ntoa(ipaddr), sport);
		total_from_server += bytes_read;
		if (total_from_server >= read_limit) {
			/* read limit hit, process attack string */
			logmsg(LOG_WARN, 1, "%s %u\t  Warning - Byte limit (%d) hit. Closing %s connections.\n",
				logpre, dport, read_limit, logact);
			close(server_sock_fd);
			close(connection_fd);
	    		return(process_data(attack_string, total_bytes, server_string, total_from_server, dport, attack));
		}
	    } else if (retval == 0) {
		/* remote host closed server connection */
		logmsg(LOG_INFO, 1, "%s %u\t  %s connection closed by foreign host.\n", logpre, dport, Logstr);
		close(connection_fd);
	    	return(process_data(attack_string, total_bytes, server_string, total_from_server, dport, attack));
	    } else {
		/* tcpcopy error */
		logmsg(LOG_INFO, 1, "%s %u\t  Error - Unable to %s data to client connection.\n", logpre, dport, logact);
		if (close(server_sock_fd) == -1)
		    logmsg(LOG_ERR, 1, "%s %u\t  Error - Unable to close %s sockt.\n", logpre, dport, logstr);
		else logmsg(LOG_NOISY, 1, "%s %u\t  %s connection closed.\n", logpre, dport, Logstr);
		close(connection_fd);
	    	return(process_data(attack_string, total_bytes, server_string, total_from_server, dport, attack));
	    }
	} else if (FD_ISSET(connection_fd, &rfds)) {
	/* read data and proxy it to server connection */
	    bytes_read = 0;
	    if ((retval= tcpcopy(server_sock_fd, connection_fd, &attack_string, total_bytes, &bytes_read, &bytes_sent))>0) {
		logmsg(LOG_INFO, 1, "%s %u\t* %u (of %u) bytes copied from client connection to %s:%u.\n",
			logpre, dport, bytes_sent, bytes_read, inet_ntoa(ipaddr), dport);
		total_bytes += bytes_read;
		if (total_from_server >= read_limit) {
			/* read limit hit, process attack string */
			logmsg(LOG_WARN, 1, "%s %u\tWarning - Byte limit (%d) hit. Closing %s connections.\n",
				logpre, dport, read_limit, logact);
			close(server_sock_fd);
			close(connection_fd);
	    		return(process_data(attack_string, total_bytes, server_string, total_from_server, dport, attack));
		}
	    } else if (retval == 0) {
		/* remote host closed client connection */
		logmsg(LOG_INFO, 1, "%s %u\t  Connection closed by foreign host.\n", logpre, dport);
		close(server_sock_fd);
		logmsg(LOG_NOISY, 1, "%s %u\t  %s connection closed.\n", logpre, dport, Logstr);
		close(connection_fd);
	    	return(process_data(attack_string, total_bytes, server_string, total_from_server, dport, attack));
	    } else {
		/* tcpcopy error */
		logmsg(LOG_INFO, 1, "%s %u\t  Error - Unable to %s data to %s connection.\n", logpre, dport, logact,logstr);
		close(connection_fd);
	    	return(process_data(attack_string, total_bytes, server_string, total_from_server, dport, attack));
	    }
	} else {
		/* select() timed out, close connections */
		logmsg(LOG_INFO, 1, "%s %u\t  %s connection timed out, closing connections.\n", logpre, dport, Logstr);
		close(server_sock_fd);
	    	return(process_data(attack_string, total_bytes, server_string, total_from_server, dport, attack));
	}
    }
}
