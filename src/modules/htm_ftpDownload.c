/* htm_ftpDownload.c
 * Copyright (C) 2006-2015 Tillmann Werner <tillmann.werner@gmx.de>
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
 * Description:
 *   This honeytrap module parses an attack string for ftp download commands.
 *   It performs the downloads with an own ftp implementation.
 */

#define _GNU_SOURCE 1

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <unistd.h>

#include <conftree.h>
#include <honeytrap.h>
#include <logging.h>
#include <md5.h>
#include <plughook.h>
#include <signals.h>
#include <sock.h>
#include <tcpip.h>
#include <util.h>

#include "htm_ftpDownload.h"

const char module_name[]="ftpDownload";
const char module_version[]="1.0.1";

char *ftp_host = NULL;

static const char *plugin_config_keywords[] = {
	"ftp_host"
};


void plugin_config(void) {
	plugin_register_confopts();
	return;
}

void plugin_init(void) {
	plugin_register_hooks();
	return;
}

void plugin_unload(void) {
	unhook(PPRIO_ANALYZE, module_name, "cmd_parse_for_ftp");
	return;
}

void plugin_register_hooks(void) {
	logmsg(LOG_DEBUG, 1, "    Plugin %s: Registering hooks.\n", module_name);
	add_attack_func_to_list(PPRIO_ANALYZE, module_name, "cmd_parse_for_ftp", (void *) cmd_parse_for_ftp);

	return;
}

void plugin_register_confopts(void) {
	int	i;
	char	full_name[264], *confopt;

	/* assemble plugin config key */
	memset(full_name, 0, 264);
	strncpy(full_name, "plugin-", 7);
	strncpy(&full_name[7], module_name, 256 < strlen(module_name) ? 256 : strlen(module_name));
	if (add_keyword(&config_keywords_tree, full_name, NULL, 0) == NULL) {
		fprintf(stderr, "  Error - Unable to add configuration keyword to tree.\n");
		exit(EXIT_FAILURE);
	}	

	/* build tree of allowed configuration keywords */
	for (i=0; i<sizeof(plugin_config_keywords)/sizeof(char *); i++) {

		/* assemble full config option path */
		if ((confopt = malloc(strlen(full_name)+strlen(plugin_config_keywords[i])+2)) == NULL) {
			fprintf(stderr, "  Error - Unable to allocate memory: %s.\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
		memset(confopt, 0, strlen(full_name)+strlen(plugin_config_keywords[i])+2);
		strcat(confopt, full_name);
		strcat(confopt, ".");
		strcat(confopt, plugin_config_keywords[i]);

		/* add config option to tree */
		if (add_keyword(&config_keywords_tree, confopt, NULL, 0) == NULL) {
			fprintf(stderr, "  Error - Unable to add configuration keyword to tree.\n");
			exit(EXIT_FAILURE);
		}	
		free(confopt);
	}
	return;
}

int cmd_parse_for_ftp(Attack *attack) {
	int i=0;
	char *string_for_processing;
	struct in_addr *addr = NULL;

	/* no data - nothing todo */
	if ((attack->a_conn.payload.size == 0) || (attack->a_conn.payload.data == NULL)) {
		logmsg(LOG_DEBUG, 1, "FTP download - No data received, nothing to download.\n");
		return(0);
	}

	logmsg(LOG_DEBUG, 1, "FTP download - Parsing attack string (%d bytes) for ftp commands.\n", attack->a_conn.payload.size);

	string_for_processing = (char *) malloc(attack->a_conn.payload.size + 1);
	memcpy(string_for_processing, attack->a_conn.payload.data, attack->a_conn.payload.size);
	string_for_processing[attack->a_conn.payload.size] = 0;
	
	for (i=0; i<attack->a_conn.payload.size; i++) {
		if ((attack->a_conn.payload.size-i >= 3)
			&& (memcmp(string_for_processing+i, "ftp", 3) == 0)) {
			logmsg(LOG_DEBUG, 1, "FTP download - FTP command found.\n");

			/* do ftp download */
			addr = (struct in_addr *) &(attack->a_conn.l_addr);
			get_ftpcmd(string_for_processing, attack->a_conn.payload.size, *addr,attack);
			return(0);
		}
	}
	logmsg(LOG_DEBUG, 1, "FTP download - No ftp command found.\n");
	return(0);
}

int get_ftpcmd(char *attack_string, uint32_t string_size, struct in_addr lhost, Attack *attack) {
	char *parse_string=NULL, port[6], *user=NULL, *pass=NULL, *file=NULL;
	struct hostent *host=NULL;
	struct strtk token;
	int i;

	for (i=0; i<string_size && parse_string == NULL; i++) {
		parse_string = attack_string+i;
		if ((parse_string = strstr(parse_string, "open")) != NULL) {
			/* extract ftp information */

			/* find host */
			parse_string += 4;
			token = extract_token(parse_string);
			parse_string += token.offset;

			logmsg(LOG_DEBUG, 1, "FTP download - Host found: %s\n", token.string);
			if ((host = gethostbyname(token.string)) == NULL) {
				logmsg(LOG_ERR, 1, "FTP download error - Unable to resolve %s: %s.\n",
					token.string, strerror(errno));
				return(-1);
			}
			logmsg(LOG_DEBUG, 1, "FTP download - %s resolves to %s.\n", token.string,
				inet_ntoa(*(struct in_addr*)host->h_addr));

			if (!replace_private_ips && !valid_ipaddr(*(struct in_addr*)host->h_addr)) {
				logmsg(LOG_INFO, 1, "FTP download error - %s is not a valid ip address.\n",
					inet_ntoa(*(struct in_addr*)host->h_addr_list[0]));
				return(-1);
			}

			/* find port */
			token = extract_token(parse_string);
			parse_string += token.offset;
			bzero(port, 6);
			if (token.string) {
				strncpy(port, token.string, 5);			
				logmsg(LOG_DEBUG, 1, "FTP download - Port found: %s\n", port);
			} else {
				logmsg(LOG_DEBUG, 1, "FTP download - No port given, using default (21).\n");
				strncpy(port, "21", 5);			
			}

			/* find user */
			if (strstr(parse_string, "echo user ") != NULL)
				parse_string = strstr(parse_string, "echo user ") + 10;
			else if (strstr(parse_string, "echo") != NULL)
				parse_string = strstr(parse_string, "echo") + 4;
			else {
				logmsg(LOG_ERR, 1, "FTP download error - Command string parser failed.\n");
				return(-1);
			}
			token = extract_token(parse_string);
			parse_string += token.offset;
			user = token.string;
			logmsg(LOG_DEBUG, 1, "FTP download - User found: %s\n", user);

			/* find password */
			while(isspace(*parse_string)) parse_string++;
			if (*parse_string != '>') {
			/* pass after user */
				token = extract_token(parse_string);
				parse_string += token.offset;
				pass = token.string;
				logmsg(LOG_DEBUG, 1, "FTP download - Password found: %s\n", pass);
			} else if (strstr(parse_string, "echo pass ") != NULL) {
				parse_string = strstr(parse_string, "echo pass ") + 10;
				token = extract_token(parse_string);
				if (!strlen(token.string)) {
					logmsg(LOG_ERR, 1, "FTP download error - Command string parser failed.\n");
					return(-1);
				}
				parse_string += token.offset;
				pass = token.string;
				logmsg(LOG_DEBUG, 1, "FTP download - Password found: %s\n", pass);
			} else if (strstr(parse_string, "echo") != strstr(parse_string, "echo get")) {
				parse_string = strstr(parse_string, "echo ") + 5;
				token = extract_token(parse_string);
				if (!strlen(token.string)) {
					logmsg(LOG_ERR, 1, "FTP download error - Command string parser failed.\n");
					return(-1);
				}
				parse_string += token.offset;
				pass = token.string;
				logmsg(LOG_DEBUG, 1, "FTP download - Password found: %s\n", pass);
			} else {
				logmsg(LOG_DEBUG, 1,
					"FTP download - No password given, using 'root@localhost'.\n");
				pass = (char *) malloc(15);
				strncpy(pass, "root@localhost\0", 15);
			}
			
			/* find filename */
			parse_string = strstr(parse_string, "echo");
			if ((parse_string = strstr(parse_string, "get")) != NULL) {
				parse_string += 3;
				token = extract_token(parse_string);
				parse_string += token.offset;
				file = token.string;
				if (!strlen(file)) {
					if (strstr(parse_string, "echo") == NULL) {
						logmsg(LOG_ERR, 1, "FTP download error - No filename found.\n");
						return(-1);
					} else {
						parse_string = strstr(parse_string, "echo") + 4;
						token = extract_token(parse_string);
						parse_string += token.offset;
						file = token.string;
					}
				}
				if (strlen(file)) {
					logmsg(LOG_DEBUG, 1, "FTP download - Filename found: %s\n", file);
				} else {
					logmsg(LOG_ERR, 1, "FTP download error - No filename found.\n");
					return(-1);
				}
			} else {
				logmsg(LOG_ERR, 1, "FTP download error - No GET command found.\n");
				return(-1);
			}

			/* Do FTP transaction */
			return(get_ftp_resource(user, pass, (struct in_addr *) &lhost,
				(struct in_addr *) host->h_addr_list[0], atoi(port), file, attack));
		}
	}
	return(0);
}


int read_ftp_line(int control_sock_fd, char *rline, ssize_t len, int timeout) {
	int read_result;

	if ((read_result = read_line(control_sock_fd, rline, len, timeout)) == 0) { 
		logmsg(LOG_NOISY, 1, "FTP download - Control connection closed by remote host.\n");
		shutdown(control_sock_fd, 0);
		return(0);
	} else if (read_result == -1) {
		logmsg(LOG_NOISY, 1, "FTP download - Control connection timeout.\n");
		return(-1);
	} else if (read_result == -2) {
		logmsg(LOG_WARN, 1, "FTP download - FTP dialog failed.\n");
		shutdown(control_sock_fd, 1);
		return(-2);
	}
	
	// make sure line ends with newline so we can log it
	if (rline[read_result] != '\n') rline[read_result] = '\n';

	return(read_result);
}


int ftp_quit(int control_sock_fd, int data_sock_fd) {
	char rline[MAX_LINE];
	int timeout = 60;

	close(data_sock_fd);

	logmsg(LOG_NOISY, 1, "FTP download - Sending 'QUIT'.\n");
	if (write(control_sock_fd, "QUIT\r\n", 6) == 6) {
		logmsg(LOG_DEBUG, 1, "FTP download - QUIT sent.\n");
		if (read_ftp_line(control_sock_fd, rline, MAX_LINE, timeout) < 0) {
			logmsg(LOG_ERR, 1, "FTP download error - Unable to read from control socket: %s.\n", strerror(errno));
			shutdown(control_sock_fd, 1);
			return(-1);
		}
		if (strstr(rline, "221") == rline) logmsg(LOG_NOISY, 1, "FTP download - Remote host said 'Goodbye'.\n");
	} else {
		logmsg(LOG_ERR, 1, "FTP download error - Unable to write to control socket: %s.\n", strerror(errno));
		shutdown(control_sock_fd, 1);
		return(-1);
	}
	shutdown(control_sock_fd, SHUT_WR);
	return(0);
}


int get_ftp_resource(const char *user, const char* pass, struct in_addr *lhost, struct in_addr *rhost, const int port, const char *save_file, Attack *attack) {
	struct sockaddr_in local_control_socket, remote_control_socket, local_data_socket, remote_data_socket;
	int control_sock_fd, data_sock_listen_fd, data_sock_fd,
	    local_data_port, bytes_read, total_bytes, addr_len, select_return, timeout, retval;
	uint8_t *ip_octet, *binary_stream;
	struct hostent *data_host = NULL;
	struct ftp_port_t {
		uint16_t first_half:8, second_half:8;
	} ftp_port;
	char rline[MAX_LINE], rbuf[READ_SIZE], *ftp_command;
	struct timeval r_timeout;
	fd_set rfds;

	ftp_command = NULL;
	binary_stream = NULL;
	local_data_port = 1080;		/* Starting with 1080 breaks RFC, but Windows does it as well */
	select_return = -1;
	timeout = 60;
	data_sock_fd = -1;
	memset(rline, 0, MAX_LINE);

	// increase number of download tries
	attack->dl_tries++;

	/* replace private ip? */
	if (replace_private_ips && (private_ipaddr(*lhost) || !(valid_ipaddr(*lhost)))) {
		logmsg(LOG_NOISY, 1, "FTP download - Replacing private/invalid server address with attacking IP address.\n");
		lhost = (struct in_addr *) &attack->a_conn.r_addr;
	}
	
	logmsg(LOG_NOTICE, 1, "FTP download - Requesting '%s' from %s:%u.\n", save_file, inet_ntoa(*rhost), port);

	/* create socket for ftp control channel */
	logmsg(LOG_DEBUG, 1, "FTP download - Initializing FTP control channel.\n");
	if (!(control_sock_fd = socket(AF_INET, SOCK_STREAM, 0))) {
		logmsg(LOG_ERR, 1, "FTP download error - Unable to initialize FTP control channel: %s.\n", strerror(errno));
		return(-1);
	}

	// bind ftp control socket to attacked local IP address
	logmsg(LOG_DEBUG, 1, "FTP download - Binding download socket to attacked address.\n");
	memset(&local_control_socket, 0, sizeof(local_control_socket));
	local_control_socket.sin_family          = AF_INET;
	local_control_socket.sin_addr.s_addr     = *(in_addr_t *)lhost;
	if (bind(control_sock_fd, &local_control_socket, sizeof(local_control_socket)) == -1) {
		logmsg(LOG_ERR, 1, "FTP download error - Unable to initialize FTP control channel: %s.\n", strerror(errno));
		return(-1);
	}


	logmsg(LOG_DEBUG, 1, "FTP download - FTP control channel initialized.\n");

	memset(&remote_control_socket, 0, sizeof(remote_control_socket));
	remote_control_socket.sin_family          = AF_INET;
	remote_control_socket.sin_addr.s_addr     = *(in_addr_t *)rhost;
	remote_control_socket.sin_port            = htons(port);
	if (nb_connect(control_sock_fd, (struct sockaddr *) &remote_control_socket, sizeof(remote_control_socket), CONNTIMEOUT) == -1) {
		/* if network or host is unreachable try attacking address instead */
		switch(errno) {
		case ECONNREFUSED:
		case ENETUNREACH:
		case ETIMEDOUT:
		case EHOSTUNREACH:
			if (rhost != (struct in_addr *) &attack->a_conn.r_addr) {
				rhost = (struct in_addr *) &attack->a_conn.r_addr;
				remote_control_socket.sin_addr.s_addr     = *(in_addr_t *)rhost;
				logmsg(LOG_NOISY, 1, "FTP download - FTP server could not be reached, trying the attacking address (%s) instead.\n",
					inet_ntoa(*rhost));
				if (nb_connect(control_sock_fd, (struct sockaddr *) &remote_control_socket, sizeof(remote_control_socket), CONNTIMEOUT) == -1) {
					logmsg(LOG_ERR, 1, "FTP download error - Unable to connect to %s:%d: %s\n",
						inet_ntoa(*rhost), port, strerror(errno));
					close(control_sock_fd);
					return(-1);
				}
				break;
			}
		default:
			logmsg(LOG_ERR, 1, "FTP download error - Unable to connect to %s:%d: %s\n",
				inet_ntoa(*rhost), port, strerror(errno));
			close(control_sock_fd);
			return(-1);
		}
	}
	logmsg(LOG_DEBUG, 1, "FTP download - Ftp control connection to %s:%d established.\n",
		inet_ntoa(*rhost), port);

	/* do a fake Windows control dialogue */
	logmsg(LOG_NOISY, 1, "FTP download - Faking Windows FTP dialogue.\n");

	/* connected, send USER */
	while(strstr(rline, "220") != rline)
		if (read_ftp_line(control_sock_fd, rline, MAX_LINE, timeout) <= 0) return(0);

	logmsg(LOG_NOISY, 1, "FTP download - Sending 'USER %s'.\n", user);
	if (asprintf(&ftp_command, "USER %s\r\n", user) == -1) {
		logmsg(LOG_ERR, 1, "FTP download error - Unable to create USER command: %m.\n");
		return(-1);
	}

	if (write(control_sock_fd, ftp_command, strlen(ftp_command))) {
		logmsg(LOG_DEBUG, 1, "FTP download - USER sent.\n");
	} else {
		logmsg(LOG_ERR, 1, "FTP download error - Unable to write to control socket: %s.\n", strerror(errno));
		shutdown(control_sock_fd, 1);
		return(-1);
	}
		
	/* wait for 331 or 230 */
	while ((strstr(rline, "331") != rline) && (strstr(rline, "230") != rline))
		if (read_ftp_line(control_sock_fd, rline, MAX_LINE, timeout) <= 0) return(0);
	
	/* send PASS */
	while ((strstr(rline, "331") == rline) && (strstr(rline, "230") != rline)) {
		free(ftp_command);
		if (asprintf(&ftp_command, "PASS %s\r\n", pass) == -1) {
			logmsg(LOG_ERR, 1, "FTP download error - Unable to create PASS command: %m.\n");
			return(-1);
		}
		if (write(control_sock_fd, ftp_command, strlen(ftp_command))) {
			logmsg(LOG_DEBUG, 1, "FTP download - PASS sent.\n");
		} else {
			logmsg(LOG_ERR, 1, "FTP download error - Unable to write to control socket: %s.\n", strerror(errno));
			shutdown(control_sock_fd, 1);
			return(-1);
		}
		if (read_ftp_line(control_sock_fd, rline, MAX_LINE, timeout) <= 0) return(0);
	}
	
	/* wait for 200 */
	while (strstr(rline, "200") != rline) {
		/* read multi-line banner */
		while ((strlen(rline) > 3) && (rline[3] == '-')) { 
			if (read_ftp_line(control_sock_fd, rline, MAX_LINE, timeout) <= 0) return(0);
		}
		/* wait for 230 and send SYST and TYPE */
		if(strstr(rline, "230") == rline) {

			/* Send SYST and switch to binary mode */
			/* Some buggy servers cannot handle a TYPE after SYST, so check for return value */
			logmsg(LOG_NOISY, 1, "FTP download - Sending 'SYST'.\n");
			if (write(control_sock_fd, "SYST\r\n", 6)) {
				logmsg(LOG_DEBUG, 1, "FTP download - SYST sent.\n");

				/* ignore a timeout, some servers stay alive even if SYST is not implemented */
				retval = read_ftp_line(control_sock_fd, rline, MAX_LINE, timeout);
				if ((retval == 0) || (retval == -2)) return(0);

				/* Some buggy servers do not support SYST and reply with a 200 or 230 */
				/* Only send TYPE if SYST timed out or was answered with a 2XX */
				if ((retval = -1) || (strstr(rline, "2") == rline)) {
					/* send TYPE to switch to binary mode */
					logmsg(LOG_NOISY, 1, "FTP download - Sending 'TYPE I'.\n");
					if (write(control_sock_fd, "TYPE I\r\n", 8)) {
						logmsg(LOG_DEBUG, 1, "FTP download - TYPE sent.\n");
						if (read_ftp_line(control_sock_fd, rline, MAX_LINE, timeout) <= 0) return(0);
						if (strstr(rline, "200") != rline)
							logmsg(LOG_DEBUG, 1,
								"FTP download - TYPE command failed.\n");
					} else {
						logmsg(LOG_ERR, 1,
							"FTP download error - Unable to write to control socket: %s.\n",
							strerror(errno));
						shutdown(control_sock_fd, 1);
						return(-1);
					}
				} else if (strstr(rline, "200") != rline) 
					logmsg(LOG_DEBUG, 1, "FTP download - SYST command failed.\n");
			} else {
				logmsg(LOG_ERR, 1, "FTP download error - Unable to write to control socket: %s.\n",
					strerror(errno));
				shutdown(control_sock_fd, 1);
				return(-1);
			}
		}
		/* read next line */
		if ((strstr(rline, "200") != rline) && (read_ftp_line(control_sock_fd, rline, MAX_LINE, timeout) <= 0)) return(0);
	}

	/* create listening socket for ftp data channel and send PORT */
	logmsg(LOG_DEBUG, 1, "FTP download - Initializing ftp data channel.\n");
	if (!(data_sock_listen_fd = socket(AF_INET, SOCK_STREAM, 0))) {
		logmsg(LOG_ERR, 1, "FTP download error - Unable to initialize FTP data channel: %s.\n", strerror(errno));
		shutdown(control_sock_fd, 1);
		return(-1);
	}

	/* set local IP address for data connection */
	if (ftp_host) {
		/* use this ip address (host) for data connection */
		logmsg(LOG_DEBUG, 1, "FTP download - Accept data connections on %s.\n", ftp_host);
		if ((data_host = gethostbyname(ftp_host)) == NULL) {
			logmsg(LOG_ERR, 1, "FTP download error - Unable to resolve %s.\n", ftp_host);
			return(-1);
		}
		logmsg(LOG_DEBUG, 1, "FTP download - %s resolves to %s.\n", ftp_host,
			inet_ntoa(*(struct in_addr*)data_host->h_addr_list[0]));

		if (!valid_ipaddr(*(struct in_addr*)data_host->h_addr)) {
			logmsg(LOG_INFO, 1, "FTP download error - %s is not a valid ip address.\n",
				inet_ntoa(*(struct in_addr*)data_host->h_addr_list[0]));
			return(-1);
		}
		lhost = (struct in_addr*)data_host->h_addr_list[0];
	} else {
		/* determine local IP address of control connection socket */
		addr_len = sizeof(struct sockaddr_in);
		if (getsockname(control_sock_fd, (struct sockaddr *) &remote_control_socket, (socklen_t *) &addr_len) != 0) {
			logmsg(LOG_ERR, 1, "FTP download error - Unable to get local address from FTP control connection socket: %s\n", strerror(errno));
			return(-1);
		}
	}
	ip_octet = (u_int8_t *) lhost;

	/* listen on data channel socket */
	memset(&local_data_socket, 0, sizeof(local_data_socket));
	local_data_socket.sin_family		= AF_INET;
	local_data_socket.sin_addr.s_addr	= remote_control_socket.sin_addr.s_addr;
	local_data_socket.sin_port		= htons(local_data_port);

	/* TODO: Check if errno == EINVAL (socket in use) */
	while(((bind(data_sock_listen_fd, (struct sockaddr *) &local_data_socket,
		sizeof(local_data_socket))) < 0) && (local_data_port < 65535)) {
		logmsg(LOG_DEBUG, 1,
			"FTP download - Unable to bind port %d. Trying port %d.\n",
			ntohs(local_data_socket.sin_port), ntohs(local_data_socket.sin_port)+1);
		/* check if integer was overflowed to 0 */
		if((local_data_socket.sin_port = htons(++local_data_port)) == 0) {
			logmsg(LOG_WARN, 1,
				"FTP download - No local ports for FTP data channel left.\n");
			close(data_sock_listen_fd);
			shutdown(control_sock_fd, 1);
			return(-1);
		}
	}
	memcpy(&ftp_port, &local_data_socket.sin_port, sizeof(local_data_socket.sin_port));
	logmsg(LOG_DEBUG, 1, "FTP download - FTP data channel on port %d initialized.\n",
		ntohs(local_data_socket.sin_port));

	if ((listen(data_sock_listen_fd, 0)) < 0) {
		logmsg(LOG_ERR, 1,
			"FTP download error - Unable to create listening socket for data channel: %s.\n",
			strerror(errno));
		close(data_sock_listen_fd);
		ftp_quit(control_sock_fd, data_sock_fd);
		return(-1);
	} else logmsg(LOG_DEBUG, 1, "FTP download - Initialized FTP data channel on port %u/tcp.\n",
		ntohs(local_data_socket.sin_port));

	/* send PORT */
	logmsg(LOG_NOISY, 1, "FTP download - Sending 'PORT %u,%u,%u,%u,%u,%u.\n",
		ip_octet[0], ip_octet[1], ip_octet[2], ip_octet[3],
		ftp_port.first_half, ftp_port.second_half);
	free(ftp_command);
	if (asprintf(&ftp_command, "PORT %u,%u,%u,%u,%u,%u\r\n", ip_octet[0], ip_octet[1],
		ip_octet[2], ip_octet[3], ftp_port.first_half, ftp_port.second_half) == -1) {
		logmsg(LOG_ERR, 1, "FTP download error - Unable to create PORT command: %m.\n");
		return(-1);
	}
	if (write(control_sock_fd, ftp_command, strlen(ftp_command)) == strlen(ftp_command)) {
		logmsg(LOG_DEBUG, 1, "FTP download - PORT sent.\n");
	} else {
		logmsg(LOG_ERR, 1, "FTP download error - Unable to write to control socket: %s.\n", strerror(errno));
		shutdown(control_sock_fd, 1);
		return(-1);
	}
	/* check if PORT was successful */
	if(strstr(rline, "4") == rline) {
		logmsg(LOG_WARN, 1, "FTP download - FTP error code received: %s", rline);
		ftp_quit(control_sock_fd, data_sock_fd);
		return(-1);
	}

	/* send RETR to retrieve file */
	logmsg(LOG_NOISY, 1, "FTP download - Sending 'RETR %s'.\n", save_file);
	free(ftp_command);
	if (asprintf(&ftp_command, "RETR %s\r\n", save_file) == -1) {
		logmsg(LOG_ERR, 1, "FTP download error - Unable to create RETR command: %m.\n");
		return(-1);
	}
	if (write(control_sock_fd, ftp_command, strlen(ftp_command))) {
		logmsg(LOG_DEBUG, 1, "FTP download - RETR sent.\n");
		free(ftp_command);
	} else {
		logmsg(LOG_ERR, 1, "FTP download error - Unable to write to control socket: %s.\n", strerror(errno));
		free(ftp_command);
		close(data_sock_fd);
		shutdown(control_sock_fd, 1);
		return(-1);
	}
	while(strstr(rline, "150") != rline) {
		/* close connection on error */
		if(strstr(rline, "4") == rline) {
			logmsg(LOG_WARN, 1, "FTP download - FTP error code received: %s", rline);
			ftp_quit(control_sock_fd, data_sock_fd);
			return(-1);
		}
		if (read_ftp_line(control_sock_fd, rline, MAX_LINE, timeout) <= 0) return(0);
	}
	addr_len = sizeof(remote_data_socket);

	/* wait for incoming data connection, close connections on timeout */
	r_timeout.tv_sec = timeout;
	r_timeout.tv_usec = 0;
	logmsg(LOG_DEBUG, 1, "FTP download - Waiting for incoming FTP data connection, timeout is %d seconds.\n",
		timeout);
	FD_ZERO(&rfds);
	FD_SET(sigpipe[0], &rfds);
	FD_SET(data_sock_listen_fd, &rfds);
	switch (select_return = select(MAX(sigpipe[0], data_sock_listen_fd) + 1, &rfds, NULL, NULL, &r_timeout)) {
	case -1:
		if (errno != EINTR) {
			logmsg(LOG_ERR, 1, "FTP download error - Select on FTP data channel failed: %s.\n", strerror(errno));
			ftp_quit(control_sock_fd, data_sock_fd);
			return(-1);
		}
	case 0:
		logmsg(LOG_WARN, 1, "FTP download - Transfer timeout, no incoming data connection for %d seconds.\n",
			timeout);
		ftp_quit(control_sock_fd, data_sock_fd);
		return(-1);
	default:
		if (FD_ISSET(sigpipe[0], &rfds) && (check_sigpipe() == -1)) exit(EXIT_FAILURE);
		if (FD_ISSET(data_sock_listen_fd, &rfds)) { 
			if ((data_sock_fd = accept(data_sock_listen_fd, (struct sockaddr *) &remote_data_socket, (u_int *) &addr_len)) < 0) {
				logmsg(LOG_ERR, 1, "FTP download error - Unable to accept FTP data connection: %s\n",
					strerror(errno));
				ftp_quit(control_sock_fd, data_sock_fd);
				return(-1);
			} else logmsg(LOG_DEBUG, 1, "FTP download - Incoming data connection from %s:%u.\n",
				inet_ntoa(remote_control_socket.sin_addr), ntohs(remote_data_socket.sin_port));
			close(data_sock_listen_fd);
		} else logmsg(LOG_DEBUG, 1, "FTP download - Select on FTP data channel returned but socket is not set.\n");
	}

	/* retrieve file, read timeout is 5 seconds */
	logmsg(LOG_DEBUG, 1, "FTP download - Waiting for data on FTP data channel, timeout is 10 seconds.\n");
	FD_ZERO(&rfds);
	FD_SET(sigpipe[0], &rfds);
	FD_SET(data_sock_fd, &rfds);
	r_timeout.tv_sec = 10;
	r_timeout.tv_usec = 0;
	select_return = select(MAX(sigpipe[0], data_sock_fd) + 1, &rfds, NULL, NULL, &r_timeout);
	if (select_return < 0) {
		if (errno != EINTR) {
			logmsg(LOG_ERR, 1, "FTP download error - Select on FTP data channel failed: %s.\n", strerror(errno));
			ftp_quit(control_sock_fd, data_sock_listen_fd);
			return(-1);
		}
	} else if (select_return == 0) {
		logmsg(LOG_WARN, 1, "FTP download - Transfer timeout, no data to read for 10 seconds.\n");
		ftp_quit(control_sock_fd, data_sock_listen_fd);
		return(-1);
	} else if (FD_ISSET(data_sock_fd, &rfds)) {
		logmsg(LOG_DEBUG, 1, "FTP download - Data available, retrieving file.\n");
		/* receive file */
		total_bytes = 0;
		while((bytes_read = read(data_sock_fd, rbuf, READ_SIZE)) > 0) {
			binary_stream = (uint8_t *) realloc(binary_stream, total_bytes + bytes_read);
			memcpy(binary_stream + total_bytes, rbuf, bytes_read);
			total_bytes += bytes_read;
		}
		if (bytes_read < 0) {
			logmsg(LOG_ERR, 1, "FTP download error - Unable to read from data channel: %s.\n", strerror(errno));
			ftp_quit(control_sock_fd, data_sock_listen_fd);
			return(-1);
		}
		logmsg(LOG_NOISY, 1, "FTP download - Successfully downloaded %s.\n", save_file);
		ftp_quit(control_sock_fd, data_sock_fd);

		/* add download to attack record */
		if (total_bytes) {
			logmsg(LOG_DEBUG, 1, "FTP download - Adding download to attack record.\n");
			add_download("ftp", TCP, rhost->s_addr, port, user, pass, (const char *) save_file, NULL, binary_stream, total_bytes, attack);

			logmsg(LOG_NOTICE, 1, "FTP download - %s attached to attack record.\n", save_file);
		} else logmsg(LOG_NOISY, 1, "FTP download - No data received.\n");

		close(data_sock_fd);
		return(0);
	} else logmsg(LOG_DEBUG, 1, "FTP download - Select on FTP data channel returned but socket is not set: %s\n", strerror(errno));
	
	/* close open descriptors and return */
	while((read_ftp_line(control_sock_fd, rline, MAX_LINE, 5) && strstr(rline, "226") != rline));
	ftp_quit(control_sock_fd, data_sock_fd);
	return(0);
}
