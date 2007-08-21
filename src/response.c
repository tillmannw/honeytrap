/* response.c
 * Copyright (C) 2006-2007 Tillmann Werner <tillmann.werner@gmx.de>
 *
 * This file is free software; as a special exception the author gives
 * unlimited permission to copy and/or distribute it, with or without
 * modifications, as long as this notice is preserved.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
 * implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * This code is based on an OpenSSL-compatible implementation of the RSA
 * Data Security, * Inc. MD5 Message-Digest Algorithm, written by Solar
 * Designer <solar at openwall.com> in 2001, and placed in the public
 * domain. There's absolutely no warranty.
 *
 * This implementation is meant to be fast, but not as fast as possible.
 * Some known optimizations are not included to reduce source code size
 * and avoid compile-time configuration.
 */

#include <dirent.h>
#include <errno.h>
#include <fnmatch.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "honeytrap.h"
#include "tcpip.h"
#include "logging.h"
#include "response.h"


void unload_default_responses(void) {
	def_resp *cur_response;
	
	while(response_list) {
		cur_response = response_list->next;
		free(response_list->response);
		free(response_list);
		response_list = cur_response;
	}
	return;
}

int prepare_default_response(char *filename, uint16_t port, uint16_t proto) {
	int answer_fd, ccopy;
        u_char buffer[100];
	FILE* answer_file = NULL;
	def_resp *last_response, *new_response;

	/* allocate memory for new response */
	if ((new_response = (def_resp *) malloc(sizeof(struct def_resp))) == NULL) {
		perror("  Error - Unable to allocate memory");
		return(-1);
	} else {
		new_response->port	= port;
		new_response->proto	= proto;
		new_response->size	= 0;
		new_response->response	= NULL;
		new_response->next	= NULL;
	}
	if (!response_list) response_list = new_response;
	else { 
		/* spool to end of the list and attach new response */
		last_response = response_list;
		while (last_response->next) last_response = last_response->next;
		last_response->next = new_response;
	}

	/* read response */
	if ((proto != TCP) && (proto != UDP)) {
		fprintf(stderr, "  Error - Protocol %u is not supported.\n", proto);
		return(-1);
	}
	DEBUG_FPRINTF(stdout, "  Loading default response for port %u/%s.\n", port, PROTO(proto));
	if (((answer_fd = open(filename, O_NOCTTY | O_RDONLY, 0640)) == -1) || (!(answer_file = fopen(filename, "rb")))) {
		DEBUG_FPRINTF(stdout, "  Warning - Unable to open file '%s'\n", filename);
	} else {
		ccopy		= 0;
		while((ccopy = fread(buffer, 1, 100, answer_file))) {
			if ((new_response->response = (u_char *) realloc(new_response->response, new_response->size + ccopy)) == NULL) {
				perror("  Error - Unable to allocate memory");
				return(-1);
			} else {
				memcpy(new_response->response + new_response->size, buffer, ccopy);
				new_response->size += ccopy;
			}
		}
		if (new_response->size != 0) {
			DEBUG_FPRINTF(stdout, "  Default response string for port %u/%s successfully loaded.\n",
				port, PROTO(proto));
		} else DEBUG_FPRINTF(stdout, "  Warning - Default response file '%s' is empty.\n", filename);
	}
	fclose(answer_file);
	close(answer_fd);
	return(0);
}


int load_default_responses(char *dir) {
	struct stat statbuf;
	struct dirent **namelist;
	int n;
	uint16_t port;
	char *full_path;
	DIR *respdir;

	full_path = NULL;

	if ((respdir = opendir(dir)) == NULL) {
		perror("  Error - Unable to open response directory");
		exit(EXIT_FAILURE);
	}
	
	DEBUG_FPRINTF(stdout, "  Searching for response files in %s\n", dir);
	if ((n = scandir(dir, &namelist, 0, alphasort)) < 0) {
		perror("  Error - Unable to scan response directory");
		exit(EXIT_FAILURE);
	} else while(n--) {
		stat(namelist[n]->d_name, &statbuf);
		if ((fnmatch("*_tcp", namelist[n]->d_name, 0) == 0) || (fnmatch("*_udp", namelist[n]->d_name, 0) == 0)) {
			/* found a default response file */
			if ((full_path = (char *) malloc(strlen(dir) + strlen(namelist[n]->d_name) + 2)) == NULL) {
				perror("  Error - Unable to allocate memory");
				exit(EXIT_FAILURE);
			}
			snprintf(full_path, strlen(dir)+strlen(namelist[n]->d_name)+2, "%s/%s", dir, namelist[n]->d_name);
			DEBUG_FPRINTF(stdout, "  Response file found: %s\n", full_path);
			port = atoi(namelist[n]->d_name);
			if (fnmatch("*_tcp", namelist[n]->d_name, 0) == 0)
				prepare_default_response(full_path, port, TCP);
			else if (fnmatch("*_udp", namelist[n]->d_name, 0) == 0)
				prepare_default_response(full_path, port, UDP);
		}
		free(namelist[n]);
	}
	free(namelist);
	
	return(0);
}


int send_default_response(int connection_fd, uint16_t port, uint16_t proto, u_char timeout) {
	def_resp *cur_response = NULL;

	if ((proto != TCP) && (proto != UDP)) {
		fprintf(stderr, "  Error - Protocol %u is not supported.\n", proto);
		return(-1);
	}

	logmsg(LOG_DEBUG, 1, "Searching for default response for port %s.\n", portstr);
	
	/* advance through list to find response for port */
	cur_response = response_list;
	while(cur_response && ((cur_response->port != port) || (cur_response->proto != proto)))
		cur_response = cur_response->next;
	
	if (cur_response && (cur_response->port == port) && (cur_response->proto == proto)) {
		/* default response for port found */
		logmsg(LOG_NOISY, 1, "   %s  No data for %u second(s), sending default response.\n",
			portstr, (u_char) timeout);

		if (!(write(connection_fd, cur_response->response, cur_response->size))) return(-1);
	} else {
		logmsg(LOG_NOISY, 1, "   %s  No data for %d second(s), sending '\\n'.\n", portstr, timeout);
		if (!(write(connection_fd, "\n", 1))) return(-1);
	}
	return(0);
}

