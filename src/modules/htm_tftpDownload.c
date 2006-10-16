/* htm_tftpDownload.c
 * Copyright (C) 2006 Tillmann Werner <tillmann.werner@gmx.de>
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
 *   This honeytrap module parses an attack string for tftp download commands.
 *   It performs the downloads with an own tftp implementation.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/stat.h>
#include <netdb.h>
#include <sys/socket.h>

#include <honeytrap.h>
#include <logging.h>
#include <plughook.h>
#include <util.h>
#include <md5.h>

#include "htm_tftpDownload.h"

void plugin_init(void) {
	plugin_register_hooks();
	return;
}

void plugin_unload(void) {
	unhook(&pluginlist_process_attack, module_name, "cmd_parse_for_tftp");
	return;
}

void plugin_register_hooks(void) {
	DEBUG_FPRINTF(stdout, "    Plugin %s: Registering hooks.\n", module_name);
	add_attack_func_to_list(module_name, "cmd_parse_for_tftp", (void *) cmd_parse_for_tftp);

	return;
}

int cmd_parse_for_tftp(Attack *attack) {
	int i=0;
	char tftp_str[] = "tftp";
	char *string_for_processing;

	logmsg(LOG_DEBUG, 1, "Parsing attack string (%d bytes) for tftp commands.\n", attack->a_conn.payload.size);

	string_for_processing = (char *) malloc(attack->a_conn.payload.size + 1);
	memcpy(string_for_processing, attack->a_conn.payload.data, attack->a_conn.payload.size);
	string_for_processing[attack->a_conn.payload.size] = 0;
	
	for (i=0; i<attack->a_conn.payload.size; i++) {
		if ((attack->a_conn.payload.size-i >= strlen(tftp_str))
			&& (memcmp(string_for_processing+i, tftp_str, strlen(tftp_str)) == 0)) {
			logmsg(LOG_DEBUG, 1, "Found TFTP command in attack string.\n");

			/* do tftp download */
			return(get_tftpcmd(string_for_processing, attack->a_conn.payload.size));
		}
	}
	logmsg(LOG_DEBUG, 1, "No tftp command found.\n");
	return(0);
}


int get_tftpcmd(char *attack_string, int string_size) {
	char *parse_string=NULL, *file=NULL;
	struct hostent *host=NULL;
	struct strtk token;
	int i;

	for (i=0; i<string_size && parse_string == NULL; i++) {
		/* find host */
		parse_string = attack_string+i;
		if ((parse_string = strstr(parse_string, "tftp -i ")) != NULL) {
			parse_string += 8;
			token = extract_token(parse_string);
			parse_string += token.offset;

			logmsg(LOG_DEBUG, 1, "TFTP download - Host found: %s\n", token.string);
			if ((host = gethostbyname(token.string)) == NULL) {
				logmsg(LOG_ERR, 1, "TFTP download error - Unable to resolve %s.\n", token.string);
				return(-1);
			}
			logmsg(LOG_DEBUG, 1, "TFTP download - %s resolves to %s.\n", token.string,
				inet_ntoa(*(struct in_addr*)host->h_addr_list[0]));

			if (!valid_ipaddr((uint32_t) *(host->h_addr_list[0]))) {
				logmsg(LOG_INFO, 1, "TFTP download error - %s is not a valid ip address.\n",
					inet_ntoa(*(struct in_addr*)host->h_addr_list[0]));
				return(-1);
			}
		}
	}
	if (parse_string == NULL) {
		logmsg(LOG_ERR, 1, "TFTP download error - Unable to locate TFTP command in attack string.\n");
		return(-1);
	}
	
	/* find filename */
	if (strstr(parse_string, "GET ")) parse_string = strstr(parse_string, "GET ") + 4;
	else if (strstr(parse_string, "get ")) parse_string = strstr(parse_string, "get ") + 4;
	else {
		logmsg(LOG_ERR, 1, "TFTP download error - No GET command found.\n");
		return(-1);
	}

	/* extract filename */
	token = extract_token(parse_string);
	parse_string += token.offset;
	file = token.string;
	if (!strlen(file)) {
		logmsg(LOG_ERR, 1, "TFTP download error - No filename found.\n");
		return(-1);
	}
	logmsg(LOG_DEBUG, 1, "TFTP download - Filename found: %s\n", file);

	/* Do TFTP download */
	return(get_tftp_ressource((struct in_addr *) host->h_addr_list[0], file));
}


int tftp_quit(int data_sock_fd, int dumpfile_fd) {
	if (data_sock_fd) close(data_sock_fd);
	if (dumpfile_fd) close(dumpfile_fd);
	return(0);
}


int get_tftp_ressource(struct in_addr* host, const char *save_file) {
	struct sockaddr_in data_socket, from;
	int data_sock_fd, dumpfile_fd,
	    fromlen, select_return, bytes_sent,
	    tftp_command_size, socklen, retransmissions, received_last_packet, last_ack_packet;
	uint8_t *binary_stream;
	uint16_t tftp_opcode, tftp_errcode, tftp_blockcode, max_blockcode;
	int32_t bytes_read;
	uint32_t total_bytes;
	char rbuf[516], *tftp_command, *dumpfile_name;

	struct timeval snd_timeout;
	fd_set rfds;

	tftp_command = NULL;
	binary_stream = NULL;
	max_blockcode = 0;
	select_return = -1;
	dumpfile_fd = -1;
	socklen = sizeof(struct sockaddr_in);
	
	logmsg(LOG_NOTICE, 1, "TFTP download - Requesting '%s' from %s.\n", save_file, inet_ntoa(*host));

	if (strlen(save_file) > 503) {
		logmsg(LOG_ERR, 1, "TFTP download error - Filename too long.\n");
		return(-1);
	}

	/* connect to server */
	logmsg(LOG_DEBUG, 1, "TFTP download - Initializing connection.\n");
	if (!(data_sock_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP))) {
		logmsg(LOG_ERR, 1, "TFTP download error - Unable to initialize connection.\n");
		return(-1);
	}

	memset(&data_socket, 0, sizeof(data_socket));
	data_socket.sin_family          = AF_INET;
	data_socket.sin_addr.s_addr     = inet_addr(inet_ntoa(*(struct in_addr*)host));
	data_socket.sin_port            = htons(69);		/* the default port */
	
	logmsg(LOG_DEBUG, 1, "TFTP download - Connection to %s initialized.\n", inet_ntoa(*(struct in_addr*)host));

	tftp_command_size = 2 + strlen(save_file) + 1 + 5 + 1;		/* Request + Filename + \0, mode + \0 */
	tftp_command = (char *) malloc(tftp_command_size);
	bzero(tftp_command, tftp_command_size);
	tftp_command[1] = 1;						/* RRQ has opcode 1 */
	strncpy(tftp_command+2, save_file, strlen(save_file));
	strncpy(tftp_command+3+strlen(save_file), "octet", 5);
			
	bytes_sent = 0;
	retransmissions = 0;
	received_last_packet = 0;

	FD_ZERO(&rfds);
	FD_SET(data_sock_fd, &rfds);
	select_return = 0;

	while ((retransmissions++ < MAX_TRANSMISSION_TRIES) && !select_return) {
		/* send read request */
		if ((bytes_sent = sendto(data_sock_fd, tftp_command, tftp_command_size, 0,
				(struct sockaddr *) &data_socket, socklen)) != tftp_command_size) {
			logmsg(LOG_ERR, 1, "TFTP download error - Unable to send read request.\n");
			return(-1);
		}
		logmsg(LOG_NOISY, 1, "TFTP download - Read request sent: \"RRQ %s octet\" (%d. try)\n",
			save_file, retransmissions);

		snd_timeout.tv_sec = 5;
		snd_timeout.tv_usec = 0;

		/* wait for incoming data, close connection on timeout */
		logmsg(LOG_DEBUG, 1, "TFTP download - Waiting for incoming data, timeout is %d seconds.\n",
			(u_int16_t) snd_timeout.tv_sec);
	
		if (((select_return = select(data_sock_fd + 1, &rfds, NULL, NULL, &snd_timeout)) < 0) && (errno != EINTR)) {
			logmsg(LOG_ERR, 1, "TFTP download error - 'select' call failed.\n");
			return(-1);
		}
	}
	if (!select_return) {
		logmsg(LOG_ERR, 1, "TFTP download error - Connection timed out.\n");
		return(-1);
	}
	logmsg(LOG_DEBUG, 1, "TFTP download - RRQ successful.\n");

	free(tftp_command);
	
	total_bytes = 0;
	last_ack_packet = 0;
	fromlen = sizeof(from);

	/* read incoming data from socket */
	while (!received_last_packet&& ((errno == EINTR) || FD_ISSET(data_sock_fd, &rfds))) {
		if ((bytes_read = recvfrom(data_sock_fd, rbuf, 516, 0, (struct sockaddr *) &from, &fromlen)) == -1) {
			logmsg(LOG_ERR, 1, "TFTP download error - Receiving data from remote host failed.\n");
			return(-1);
		}
		if (data_socket.sin_port != from.sin_port) {
			data_socket.sin_port = from.sin_port;
			logmsg(LOG_NOISY, 1, "TFTP download - Remote host uses port %d/udp.\n", data_socket.sin_port);
		}
		
		memcpy(&tftp_opcode, rbuf, 2);

		switch(ntohs(tftp_opcode)) {
			case 3:
				/* Got data */
				memcpy(&tftp_blockcode, rbuf+2, 2);
				logmsg(LOG_DEBUG, 1, "TFTP download - Data block %u read (%u bytes).\n",
					ntohs(tftp_blockcode), bytes_read);

				if (last_ack_packet >= ntohs(tftp_blockcode)) {
					/* packet already processed and acknowledged */
					logmsg(LOG_DEBUG, 1, "TFTP download - Data block %u re-received (%u bytes).\n",
						ntohs(tftp_blockcode), bytes_read);
				} else {
					/* new packet */
					last_ack_packet = ntohs(tftp_blockcode);
					total_bytes += bytes_read-4;	/* subtract space for opcode and block number */
				
					/* check if we need to insert packet into file */
					if (ntohs(tftp_blockcode) > ntohs(max_blockcode)) {
						max_blockcode = tftp_blockcode;
						binary_stream = (uint8_t *) realloc(binary_stream, total_bytes);
						/* assemble file */
						memcpy(binary_stream + total_bytes - bytes_read+4, rbuf+4, bytes_read-4);
					}
				}

				/* send ACK */
				bytes_sent = 0;
				tftp_command = (char *) malloc(4);
				bzero(tftp_command, 4);
				tftp_command[1] = 4;			/* ACK opcode */
				memcpy(tftp_command+2, &tftp_blockcode, 2);

				logmsg(LOG_DEBUG, 1, "TFTP download - ACK %u assembled.\n", ntohs(tftp_blockcode));

				if (bytes_read < 512) { 
					received_last_packet = 1;
					logmsg(LOG_DEBUG, 1, "TFTP download - Last data packet recieved.\n");
					if ((bytes_sent = sendto(data_sock_fd, tftp_command, 4, 0,
							(struct sockaddr *) &data_socket, socklen)) == -1) {
						logmsg(LOG_DEBUG, 1, "TFTP download - Unable to send last ACK packet.\n");
					} else logmsg(LOG_DEBUG, 1, "TFTP download - Data block %d acknowledged.\n",
						ntohs(tftp_blockcode));
				} else {
					retransmissions = 0;
					bytes_sent = 0;
					select_return = 0;

					while ((retransmissions++ < MAX_TRANSMISSION_TRIES) && !select_return) {
						logmsg(LOG_DEBUG, 1, "TFTP download - Sending \"ACK %u\" (%u. try)\n",
							ntohs(tftp_blockcode), retransmissions);
						if ((bytes_sent = sendto(data_sock_fd, tftp_command, 4, 0,
								(struct sockaddr *) &data_socket, socklen)) == -1) {
							logmsg(LOG_ERR, 1,
								"TFTP download error - Unable to send ACK packet.\n");
							return(-1);
						}

						snd_timeout.tv_sec = 5;
						snd_timeout.tv_usec = 0;

						if (((select_return = select(data_sock_fd + 1, &rfds, NULL, NULL,
							&snd_timeout)) < 0) && (errno != EINTR)) {
							logmsg(LOG_ERR, 1, "TFTP download error - 'select' call failed.\n");
							return(-1);
						}
					}
					if (!select_return) {
						logmsg(LOG_ERR, 1, "TFTP download error - Connection timed out.\n");
						free(binary_stream);
						return(-1);
					}
					logmsg(LOG_DEBUG, 1, "TFTP download - Data block %d acknowledged.\n",
						ntohs(tftp_blockcode));
				}
				break;
			case 5:
				/* RRQ failed */
				memcpy(&tftp_errcode, rbuf+2, 2);
				if (tftp_errcode == 1) logmsg(LOG_ERR, 1, "TFTP download error - File not found.\n");
				else logmsg(LOG_ERR, 1, "TFTP download error - Read Request failed.\n");
				return(-1);
				break;
			default:
				logmsg(LOG_DEBUG, 1, "TFTP download - %d bytes read.\n", bytes_read);
				logmsg(LOG_WARN, 1,
					"TFTP download warning - Don't know how to handle opcode %d.\n", tftp_opcode);
				break;
		}
	}
	/* store data in local file */
	if (total_bytes) {
		/* we need the length of directory + "/" + filename plus md5 checksum */
		dumpfile_name = (char *) malloc(strlen(dlsave_dir)+strlen(save_file)+35);
		snprintf(dumpfile_name, strlen(dlsave_dir)+strlen(save_file) + 35, "%s/%s-%s",
			dlsave_dir, mem_md5sum(binary_stream, total_bytes), save_file);
		logmsg(LOG_DEBUG, 1, "TFTP download - Dumpfile name is %s\n", dumpfile_name);
		if (((dumpfile_fd = open(dumpfile_name, O_WRONLY | O_CREAT | O_EXCL)) < 0) ||
		    (fchmod(dumpfile_fd, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) != 0)) {
			logmsg(LOG_ERR, 1, "TFTP download error - Unable to save %s: %s.\n", save_file,
				strerror(errno));
			tftp_quit(data_sock_fd, dumpfile_fd);
			return(-1);
		}
		if (write(dumpfile_fd, binary_stream, total_bytes) != total_bytes) { 
			logmsg(LOG_ERR, 1, "TFTP download error - Unable to save data in local file.\n");
			tftp_quit(data_sock_fd, dumpfile_fd);
			return(-1);
		}
		if (dumpfile_fd) close(dumpfile_fd);
		logmsg(LOG_NOTICE, 1, "TFTP download - %s saved.\n", save_file);
	} else logmsg(LOG_NOISY, 1, "TFTP download - No data received.\n");
	
	/* close open descriptors and return */
	return(tftp_quit(data_sock_fd, dumpfile_fd));
}
