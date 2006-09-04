/* tcpserver.c
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
#include <errno.h>
#include <string.h>

#include "honeytrap.h"
#include "logging.h"
#include "tcpserver.h"
#include "response.h"
#include "md5.h"
#include "proxy.h"
#include "plughook.h"

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


void start_tcp_server(struct in_addr ip_r, u_int16_t port_r, struct in_addr ip_l, u_int16_t port_l) {
    pid_t pid;
    int listenfd, mirror_sock_fd, proxy_sock_fd, connection_fd, disconnect, sock_option,
	client_addr_len, total_bytes, select_return, mirror_this, proxy_this;
    struct sockaddr_in client_addr, server_addr;
    struct timeval c_timeout;
    struct s_proxy_dest *proxy_dst;
    struct hostent *proxy_addr;
    struct in_addr *p_addr;
    fd_set rfds;

    proxy_addr		= NULL;
    proxy_dst		= NULL;
    attack_string	= NULL;
    select_return	= -1;
    mirror_sock_fd	= -1;
    proxy_sock_fd	= -1;
    proxy_this		= 0;


    logmsg(LOG_DEBUG, 1, "-> %u\t  Connection request from %s, forking server process.\n",
	    (uint16_t) ntohs(port_l), inet_ntoa(ip_r));


    /* check for explicit port configuration */
    switch (port_flags[ntohs(port_l)]) {
    case PORTCONF_NONE:
	logmsg(LOG_DEBUG, 1, "Port %u/tcp has no explicit configuration.\n", ntohs(port_l));
	break;
    case PORTCONF_IGNORE:
	logmsg(LOG_DEBUG, 1, "Port %u/tcp is configured to be ignored.\n", ntohs(port_l));
	return;
    case PORTCONF_NORMAL:
	logmsg(LOG_DEBUG, 1, "Port %u/tcp is configured to be handled in normal mode.\n", ntohs(port_l));
	break;
    case PORTCONF_MIRROR:
	logmsg(LOG_DEBUG, 1, "Port %u/tcp is configured to be handled in mirror mode.\n", ntohs(port_l));
	break;
    case PORTCONF_PROXY:
	logmsg(LOG_DEBUG, 1, "Port %u/tcp is configured to be handled in proxy mode\n", ntohs(port_l));
	break;
    default:
	logmsg(LOG_ERR, 1, "Error - Invalid explicit configuration for port %u/tcp.\n", ntohs(port_l));
	return;
    }


    /* fork server process */
    if ((pid = fork()) == 0) {
	if (!(listenfd = socket(AF_INET, SOCK_STREAM, 0))) {
	    logmsg(LOG_ERR, 1, "Error - socket() call failed: %s\n", strerror(errno));
	    exit(1);
	}

	sock_option = 1;
	if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &sock_option, sizeof(sock_option)) < 0)
	logmsg(LOG_WARN, 1, "Warning - Unable to set SO_REUSEADDR on listening socket.\n");

	bzero((char *) &server_addr, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	server_addr.sin_port = port_l;
	if ((bind(listenfd, (struct sockaddr *) &server_addr, sizeof(server_addr))) < 0) {
	    /* do not warn if errno = 98 (address already in use) */
	    if (errno != 98) logmsg(LOG_NOISY, 1, "Warning - bind() call failed for port %u/tcp: %s, errno is %d\n",
		(uint16_t) ntohs(port_l), strerror(errno), errno);
	    close(listenfd);
	    exit(1);
	}   

	drop_privileges(); 
	logmsg(LOG_DEBUG, 1, "Server is now running with user id %d and group id %d.\n", getuid(), getgid());
		  

	if ((listen(listenfd, 0)) < 0) {
	    logmsg(LOG_ERR, 1, "Error - listen() call failed: %s\n", strerror(errno));
	    close(listenfd);
	    exit(1);
	}
	
	client_addr_len = sizeof(client_addr);

	/* wait for incoming connections */
	for (;;) {
	    FD_ZERO(&rfds);
	    FD_SET(listenfd, &rfds);
	    c_timeout.tv_sec = conn_timeout;
	    c_timeout.tv_usec = 0;
	    select_return = select(listenfd + 1, &rfds, NULL, NULL, &c_timeout);

	    if (select_return < 0) {
		if (errno != EINTR) {
		    logmsg(LOG_ERR, 1, "Error - select() call failed: %s\n", strerror(errno));
		    exit(1);
		}
	    } else if (select_return == 0) {
		/* timeout */
		logmsg(LOG_NOISY, 1, "-> %u\t  No incoming connection for %u seconds - server terminated.\n",
		    (uint16_t) ntohs(port_l), conn_timeout);
		exit(0);
	    } else {
		if (FD_ISSET(listenfd, &rfds)) {
		    logmsg(LOG_NOISY, 1, "   %u\t  Connection request from %s.\n",
			(uint16_t) ntohs(port_l), inet_ntoa(ip_r));
		    mirror_this = mirror_mode;

		    if (port_flags[ntohs(port_l)] & PORTCONF_NORMAL) {
		    	/* handle connection in normal mode if this port configured to be handled 'normal' */
			logmsg(LOG_DEBUG, 1, "Handling connection in normal mode.\n");
			mirror_this = 0;
			proxy_this = 0;
		    } else if (port_flags[ntohs(port_l)] & PORTCONF_PROXY) {
			/* get proxy server for port */
			logmsg(LOG_DEBUG, 1, "Handling connection in proxy mode.\n");
			proxy_dst = proxy_dest;
			while (proxy_dst) {
			    if (proxy_dst->attack_port == ntohs(port_l)) break;
			    proxy_dst = proxy_dst->next;
			}
			if (proxy_dst->attack_port == ntohs(port_l)) {
				/* try establish proxy connection to server */
                            if ((proxy_addr = gethostbyname(proxy_dst->d_addr)) == NULL) {
                                logmsg(LOG_ERR, 1, "Error - Unable to resolve proxy host %s.\n", proxy_dst->d_addr);
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
				    ntohs(port_l), proxy_dst->d_port)) == -1) {
				    logmsg(LOG_INFO, 1,
					"== %u\t  Proxy connection rejected, falling back to normal mode.\n",
					(uint16_t) ntohs(port_l));
				    proxy_this = 0;
				} else logmsg(LOG_NOTICE, 1, "== %u\t  Proxy connection to %s:%u established.\n",
				    (uint16_t) ntohs(port_l),
				    inet_ntoa(*(struct in_addr*)proxy_addr->h_addr_list[0]), proxy_dst->d_port);
			}
		    } else if ((mirror_this) || (port_flags[ntohs(port_l)] & PORTCONF_MIRROR)) {
			/* try to establish mirror connection back to the client */
			logmsg(LOG_DEBUG, 1, "Handling connection in mirror mode.\n");

			logmsg(LOG_DEBUG, 1, "<> %u\t  Requesting mirror connection to %s:%u.\n",
			    (uint16_t) ntohs(port_l), inet_ntoa(ip_r), ntohs(port_l));
			if ((mirror_sock_fd = proxy_connect(PORTCONF_MIRROR,
			    (struct in_addr) ip_r, ntohs(port_l), ntohs(port_l))) == -1) {
			    logmsg(LOG_INFO, 1, "<> %u\t  Mirror connection rejected, falling back to normal mode.\n",
				(uint16_t) ntohs(port_l));
			    mirror_this = 0;
			} else logmsg(LOG_NOTICE, 1, "<> %u\t  Mirror connection to %s:%u established.\n",
			    (uint16_t) ntohs(port_l), inet_ntoa(ip_r), (uint16_t) ntohs(port_l));
		    }

		    /* accept connection request */
		    if ((connection_fd = accept(listenfd, (struct sockaddr *) &client_addr, &client_addr_len)) < 0) {
			if (errno == EINTR) break;
			else {
			    logmsg(LOG_ERR, 1, "Error - accept() call failed: %s\n", strerror(errno));
			    close(mirror_sock_fd);
			    exit(1);
			}
		    } else {
			/* accept successful, fork process and handle connection */
					
			logmsg(LOG_NOTICE, 1, "   %u\t  Connection accepted from %s:%u.\n",
			    (uint16_t) ntohs(port_l), inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
			if ((pid = fork()) == 0) {
			    /* close listening socket in child */
			    close(listenfd);
			    disconnect = 0;
			    total_bytes = 0;

			    /* initialize attack record */
			    init_attack(connection_fd, ip_l, client_addr.sin_addr,
					ntohs(server_addr.sin_port), ntohs(client_addr.sin_port));

			    if ((proxy_this) || (port_flags[ntohs(port_l)] & PORTCONF_PROXY)) {
				logmsg(LOG_DEBUG, 1, "   %u\t  Handling connection from %s:%u in proxy mode.\n",
				    (uint16_t) ntohs(port_l), inet_ntoa(client_addr.sin_addr),
				    ntohs(client_addr.sin_port));
				handle_connection_proxied(connection_fd, PORTCONF_PROXY, proxy_sock_fd,
				    (uint16_t) ntohs(port_l), client_addr.sin_port,
				    client_addr.sin_addr, m_read_timeout, read_timeout);
				exit(0);
			    } else if ((mirror_this) || (port_flags[ntohs(client_addr.sin_port)] & PORTCONF_MIRROR)) {
				logmsg(LOG_DEBUG, 1, "   %u\t  Handling connection from %s:%u in mirror mode.\n",
				    (uint16_t) ntohs(port_l), inet_ntoa(client_addr.sin_addr),
				    ntohs(client_addr.sin_port));
				handle_connection_proxied(connection_fd, PORTCONF_MIRROR, mirror_sock_fd,
				    (uint16_t) ntohs(port_l), client_addr.sin_port,
				    client_addr.sin_addr, m_read_timeout, read_timeout);
				exit(0);
			    } else {
				logmsg(LOG_DEBUG, 1, "   %u\t  Handling connection from %s:%u in normal mode.\n",
				    (uint16_t) ntohs(port_l), inet_ntoa(client_addr.sin_addr),
				    ntohs(client_addr.sin_port));
				handle_connection_normal(connection_fd, (uint16_t) ntohs(port_l), read_timeout);
				exit(0);
			    }

			} else if (pid == -1) logmsg(LOG_ERR, 1, "Error - forking connection handler failed.\n");
			close(mirror_sock_fd);
			close(connection_fd);
		    } /* connection accepted */
		} /* FD_ISSET - incoming connection */
	    } /* select return for listenfd */	
	} /* for - incoming connections */
	/* end server process */
    } /* fork - server process */
    else if (pid == -1) logmsg(LOG_ERR, 1, "Error - forking server process failed.\n");
    return;
}


/* handle connection in normal mode - respond with default answers */
int handle_connection_normal(int connection_fd, uint16_t port, u_char timeout) {
    fd_set rfds;
    struct timeval r_timeout;
    int disconnect, bytes_read, total_bytes;
	    
    total_bytes	= 0;
    disconnect	= 0;

    /* read data from sockets */
    for (;;) {
	FD_ZERO(&rfds);
	FD_SET(connection_fd, &rfds);

	if (((uint16_t) ntohs(port) == 80)
	    || ((uint16_t) ntohs(port) == 135)
	    || ((uint16_t) ntohs(port) == 139)
	    || ((uint16_t) ntohs(port) == 445)
	    || ((uint16_t) ntohs(port) == 1433) 
	    || ((uint16_t) ntohs(port) == 4444)) {
	    conn_timeout = 2;
	    disconnect++;
	} else disconnect += 2;

	r_timeout.tv_sec = (u_char) timeout;
	r_timeout.tv_usec = 0;
	if ((select(connection_fd + 1, &rfds, NULL, NULL, &r_timeout) < 0) && (errno != EINTR)) {
	    logmsg(LOG_ERR, 1, "Error - %u\t  Select failed - connection handler terminated.\n", port);
	    close(connection_fd);
	    return(process_data(attack_string, total_bytes, NULL, 0, attack.a_conn.l_port));
	}

	/* handle data on server connection */
	if (FD_ISSET(connection_fd, &rfds)) {
	    if ((bytes_read = read(connection_fd, buffer, sizeof(buffer))) > 0) {
		logmsg(LOG_INFO, 1, "   %u\t* %d bytes read.\n", port, bytes_read);
		total_bytes += bytes_read;
		if (!(attack_string = (u_char *) realloc(attack_string, total_bytes))) {
		    logmsg(LOG_ERR, 1, "Error - %u\t  Reallocating buffer size failed.\n", port);
		    free(attack_string);
		    return(-1);
		}
		memcpy(attack_string + total_bytes - bytes_read, buffer, bytes_read);
    		disconnect = 0;
		/* check if read limit was hit */
		if (bytes_read >= read_limit) {
			/* read limit hit, process attack string */
			logmsg(LOG_WARN, 1, "%u\t  Warning - Byte limit (%d) hit. Closing connection.\n", read_limit, port);
			close(connection_fd);
			return(process_data(attack_string, total_bytes, NULL, 0, attack.a_conn.l_port));
		}
	    } else {
		logmsg(LOG_INFO, 1, "   %u\t  Connection closed by foreign host.\n", port);

		/* process attack string */
		close(connection_fd);
		return(process_data(attack_string, total_bytes, NULL, 0, attack.a_conn.l_port));
	    }
	} else {
	    /* no data available, select timed out */
	    if (disconnect > 5) {
		logmsg(LOG_INFO, 1, "   %u\t  Timeout expired, closing connection.\n", port);

		/* process attack string */
		close(connection_fd);
		return(process_data(attack_string, total_bytes, NULL, 0, attack.a_conn.l_port));
	    } else {
		if ((!send_default_response(connection_fd, port, read_timeout)) == -1) {
		    logmsg(LOG_ERR, 1, "   %u\t  Response failed. Closing socket.\n", port);
		    close(connection_fd);
		    return(process_data(attack_string, total_bytes, NULL, 0, attack.a_conn.l_port));
		}
	    } /* disconnect check */
	} /* FD_ISSET */
    } /* for */
}


/* process attack - call plugins registered for hook 'process_attack' */
int process_data(u_char *a_data, uint32_t a_size, u_char *m_data, uint32_t m_size, uint16_t port) {

	/* save end time and payload data in attack record */
	time(&attack.end_time);
	/* attack string */
	attack.a_conn.payload.size = a_size;
	if (a_size) {
		attack.a_conn.payload.data = (char *) malloc(a_size);
		memcpy(attack.a_conn.payload.data, a_data, a_size);
	}

	memcpy(attack.a_conn.payload.chksum, (char*)mem_md5sum(attack.a_conn.payload.data, attack.a_conn.payload.size), 33);
	/* mirror string */
	attack.m_conn.payload.size = m_size;
	if (m_size) {
		attack.m_conn.payload.data = (char *) malloc(m_size);
		memcpy(attack.m_conn.payload.data, m_data, m_size);
	}
	memcpy((char *) &(attack.m_conn.payload.chksum),
		(char *) mem_md5sum(attack.m_conn.payload.data, attack.m_conn.payload.size), 32);


	if (!a_size) {
		logmsg(LOG_NOTICE, 1, " * %u\t  No bytes received from %s:%u.\n",
		(uint16_t) attack.a_conn.l_port, inet_ntoa(attack.a_conn.r_addr), attack.a_conn.r_port);
	} else {
		logmsg(LOG_NOTICE, 1, " * %u\t  %d bytes attack string from %s:%u.\n",
			(uint16_t) attack.a_conn.l_port, a_size,
			inet_ntoa(attack.a_conn.r_addr), attack.a_conn.r_port);
	}

	/* call plugins */
	/* do calls even if no data received, i.e. to update connection statistics */
	plughook_process_attack(attack);

	return(1);
}


void init_attack(int fd, struct in_addr l_addr, struct in_addr r_addr, uint16_t l_port, uint16_t r_port) {
	/* clean attack record */
	if (attack.a_conn.payload.data) free(attack.a_conn.payload.data);	/* free attack data */
	if (attack.m_conn.payload.data) free(attack.m_conn.payload.data);	/* free mirror data */
	if (attack.p_conn.payload.data) free(attack.p_conn.payload.data);	/* free proxy data */
	attack.a_conn.payload.data = NULL;
	attack.m_conn.payload.data = NULL;
	attack.p_conn.payload.data = NULL;
	bzero(&attack.a_conn.payload, sizeof(struct s_payload));
	bzero(&attack.m_conn.payload, sizeof(struct s_payload));
	bzero(&attack.p_conn.payload, sizeof(struct s_payload));
	bzero(&attack.a_conn, sizeof(struct s_conn));
	bzero(&attack.m_conn, sizeof(struct s_conn));
	bzero(&attack.p_conn, sizeof(struct s_conn));
	bzero(&attack, sizeof(struct s_attack));

	/* store attack connection data in attack record */
	attack.a_conn.l_addr	= l_addr;
	attack.a_conn.r_addr	= r_addr;
	attack.a_conn.l_port	= l_port;
	attack.a_conn.r_port	= r_port;
	time(&attack.start_time);

	return;
}


/* tcpcopy - reads data from one connection and writes it to another *
 * also store read data in 'save_string' at position 'offset' */
int tcpcopy(int to_fd, int from_fd, u_char **save_string, uint32_t offset, int *bytes_read, int *bytes_sent) {
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



/* handle connection in proxy or mirror mode
 * - in proxy mode connections are proxied to configured hosts 
 * - in mirror mode all data mirrored from the connecting client back to itself and vice versa */
int handle_connection_proxied(int connection_fd, u_char mode, int server_sock_fd, uint16_t dport, uint16_t sport, struct in_addr ipaddr, u_char timeout, u_char fb_timeout) {
    fd_set rfds;
    struct timeval r_timeout;
    int disconnect, bytes_read, bytes_sent, total_bytes, total_from_server, max_read_fd, retval;
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

	max_read_fd = (server_sock_fd > connection_fd ? server_sock_fd : connection_fd);

	r_timeout.tv_sec = (u_char) timeout;
	r_timeout.tv_usec = 0;
	if ((select(connection_fd + 1, &rfds, NULL, NULL, &r_timeout) < 0) && (errno != EINTR)) {
	    logmsg(LOG_INFO, 1, "%s %u\t  Error - Select failed: %s.\n", logpre, dport, strerror(errno));
	    close(server_sock_fd);
	    close(connection_fd);
	    return(process_data(attack_string, total_bytes, server_string, total_from_server, dport));
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
	    		return(process_data(attack_string, total_bytes, server_string, total_from_server, dport));
		}
	    } else if (retval == 0) {
		/* remote host closed server connection */
		logmsg(LOG_INFO, 1, "%s %u\t  %s connection closed by foreign host.\n", logpre, dport, Logstr);
		close(connection_fd);
	    	return(process_data(attack_string, total_bytes, server_string, total_from_server, dport));
	    } else {
		/* tcpcopy error */
		logmsg(LOG_INFO, 1, "%s %u\t  Error - Unable to %s data to client connection.\n", logpre, dport, logact);
		if (close(server_sock_fd) == -1)
		    logmsg(LOG_ERR, 1, "%s %u\t  Error - Unable to close %s sockt.\n", logpre, dport, logstr);
		else logmsg(LOG_NOISY, 1, "%s %u\t  %s connection closed.\n", logpre, dport, Logstr);
		close(connection_fd);
	    	return(process_data(attack_string, total_bytes, server_string, total_from_server, dport));
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
	    		return(process_data(attack_string, total_bytes, server_string, total_from_server, dport));
		}
	    } else if (retval == 0) {
		/* remote host closed client connection */
		logmsg(LOG_INFO, 1, "%s %u\t  Connection closed by foreign host.\n", logpre, dport);
		close(server_sock_fd);
		logmsg(LOG_NOISY, 1, "%s %u\t  %s connection closed.\n", logpre, dport, Logstr);
		close(connection_fd);
	    	return(process_data(attack_string, total_bytes, server_string, total_from_server, dport));
	    } else {
		/* tcpcopy error */
		logmsg(LOG_INFO, 1, "%s %u\t  Error - Unable to %s data to %s connection.\n", logpre, dport, logact,logstr);
		close(connection_fd);
	    	return(process_data(attack_string, total_bytes, server_string, total_from_server, dport));
	    }
	} else {
		/* select() timed out, close connections */
		logmsg(LOG_INFO, 1, "%s %u\t  %s connection timed out, closing connections.\n", logpre, dport, Logstr);
		close(server_sock_fd);
		return(0);
	}
    }
}
