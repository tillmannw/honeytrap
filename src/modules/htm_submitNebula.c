/* htm_submitNebula.c
 * Copyright (C) 2008 Tillmann Werner <tillmann.werner@gmx.de>
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
 *   This honeytrap module submits attacks to a nebula server.
 */

#define _GNU_SOURCE 1

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <zlib.h>

#include <attack.h>
#include <conftree.h>
#include <honeytrap.h>
#include <logging.h>
#include <md5.h>
#include <plughook.h>
#include <readconf.h>
#include <sock.h>
#include <tcpip.h>
#include <util.h>

#include "htm_submitNebula.h"

const char module_name[]="submitNebula";
const char module_version[]="0.1.0";

static const char *config_keywords[] = {
	"host",
	"port",
	"secret"
};

const char	*nebula_secret;
const char	*nebula_host;
u_int16_t	nebula_port;


void plugin_init(void) {
	plugin_register_hooks();
	register_plugin_confopts(module_name, config_keywords, sizeof(config_keywords)/sizeof(char *));
	if (process_conftree(config_tree, config_tree, plugin_process_confopts, NULL) == NULL) {
		fprintf(stderr, "  Error - Unable to process configuration tree for plugin %s.\n", module_name);
		exit(EXIT_FAILURE);
	}
	return;
}

void plugin_unload(void) {
	unhook(PPRIO_POSTPROC, module_name, "submit_nebula");
	return;
}

void plugin_register_hooks(void) {
	DEBUG_FPRINTF(stdout, "    Plugin %s: Registering hooks.\n", module_name);
	add_attack_func_to_list(PPRIO_POSTPROC, module_name, "submit_nebula", (void *) submit_nebula);

	return;
}

conf_node *plugin_process_confopts(conf_node *tree, conf_node *node, void *opt_data) {
	char		*value = NULL;
	conf_node	*confopt = NULL;

	if ((confopt = check_keyword(tree, node->keyword)) == NULL) return(NULL);

	while (node->val) {
		if ((value = malloc(node->val->size+1)) == NULL) {
			perror("  Error - Unable to allocate memory");
			exit(EXIT_FAILURE);
		}
		memset(value, 0, node->val->size+1);
		memcpy(value, node->val->data, node->val->size);

		node->val = node->val->next;

		if OPT_IS("host") {
			nebula_host = value;
		} else if OPT_IS("port") {
			if (strtoull(value, NULL, 10) > 65535) {
				logmsg(LOG_ERR, 1, "SubmitNebula Error - Invalid port: %s\n", value);
				exit(EXIT_FAILURE);
			}
			nebula_port = strtoull(value, NULL, 10);
		} else if OPT_IS("secret") {
			nebula_secret = value;
			if (strlen(nebula_secret) > 255) {
				logmsg(LOG_ERR, 1, "SubmitNebula Error - Secret must not be longer than 255 characters.\n");
				exit(EXIT_FAILURE);
			}
		} else {
			fprintf(stderr, "  Error - Invalid configuration option for plugin %s: %s\n", module_name, node->keyword);
			exit(EXIT_FAILURE);
		}
	}
	return(node);
}

int submit_nebula(Attack *attack) {
	struct hostent		*host;
	u_char			*cbuf, response[9];
	u_int32_t		cbuf_len;
	struct sockaddr_in	sock;
	int			sock_fd;
	u_char			secret_len;

	cbuf_len	= 0;
	cbuf		= NULL;
	host		= NULL;

	/* no data - nothing todo */
	if ((attack->a_conn.payload.size == 0) || (attack->a_conn.payload.data == NULL)) {
		logmsg(LOG_DEBUG, 1, "SubmitNebula - No data received.\n");
		return(0);
	}


	if ((host = gethostbyname(nebula_host)) == NULL) {
		logmsg(LOG_ERR, 1, "SubmitNebula Error - Unable to resolve %s: %s.\n", nebula_host, strerror(errno));
		return(-1);
	}
	logmsg(LOG_NOISY, 1, "SubmitNebula - Submitting attack data to %s:%u.\n",
		inet_ntoa(*(struct in_addr*)host->h_addr), nebula_port);


	/* create socket and connect to nebula server */
	logmsg(LOG_DEBUG, 1, "SubmitNebula - Connecting to nebula server.\n");
	if (!(sock_fd = socket(AF_INET, SOCK_STREAM, 0))) {
		logmsg(LOG_ERR, 1, "SubmitNebula Error - Unable to create socket: %m.\n");
		return(-1);
	}
	memset(&sock, 0, sizeof(struct sockaddr_in));
	sock.sin_family	= AF_INET;
	sock.sin_addr	= *(struct in_addr*)host->h_addr;
	sock.sin_port	= htons(nebula_port);
	if (nb_connect(sock_fd, (struct sockaddr *) &sock, sizeof(struct sockaddr_in), CONNTIMEOUT) == -1) {
		logmsg(LOG_ERR, 1, "SubmitNebula Error - Unable to connect to %s:%u: %m\n",
			inet_ntoa(*(struct in_addr*)host->h_addr), nebula_port);
		close(sock_fd);
		return(-1);
	}
	logmsg(LOG_DEBUG, 1, "SubmitNebula - Connection to %s:%d established.\n",
		inet_ntoa(*(struct in_addr*)host->h_addr), nebula_port);

	// send secret length
	secret_len = strlen(nebula_secret);
	if (write(sock_fd, &secret_len, 1) == -1) {
		logmsg(LOG_ERR, 1, "SubmitNebula Error - Writing to socket failed: %m.\n");
		close(sock_fd);
		return(-1);
	}

	// send secret
	if (write(sock_fd, nebula_secret, secret_len) == -1) {
		logmsg(LOG_ERR, 1, "SubmitNebula Error - Writing to socket failed: %m.\n");
		close(sock_fd);
		return(-1);
	}

	// send md5 hash
	if (write(sock_fd, attack->a_conn.payload.md5sum, 32) == -1) {
		logmsg(LOG_ERR, 1, "SubmitNebula Error - Writing to socket failed: %m.\n");
		close(sock_fd);
		return(-1);
	}


	if (!read_line(sock_fd, (char *) response, 9, 10)) {
		logmsg(LOG_WARN, 1, "SubmitNebula Warning - Nebula server did not respond within 10 seconds, skipping submission.\n");
		close(sock_fd);
		return(0);
	}
	if (strncmp((char *) response, "KNOWN", 5) == 0) {
		logmsg(LOG_WARN, 1, "SubmitNebula - Attack hash is already known, skipping submission.\n");
		close(sock_fd);
		return(0);
	}
	else if (strncmp((char *) response, "UNKNOWN", 5) != 0) {
		logmsg(LOG_WARN, 1, "SubmitNebula - Nebula server returned an invalid response, skipping submission.\n");
		close(sock_fd);
		return(0);
	}
	logmsg(LOG_NOISY, 1, "SubmitNebula - Nebula server requested unknown attack, starting submission.\n");


	// send protocol 
	if (write(sock_fd, &(attack->a_conn.protocol), 1) == -1) {
		logmsg(LOG_ERR, 1, "SubmitNebula Error - Writing to socket failed: %m.\n");
		close(sock_fd);
		return(-1);
	}

	// send port (in host byte order)
	if (write(sock_fd, &(attack->a_conn.l_port), 2) == -1) {
		logmsg(LOG_ERR, 1, "SubmitNebula Error - Writing to socket failed: %m.\n");
		close(sock_fd);
		return(-1);
	}

	// send length of uncompressed attack
	if (write(sock_fd, &(attack->a_conn.payload.size), 4) == -1) {
		logmsg(LOG_ERR, 1, "SubmitNebula Error - Writing to socket failed: %m.\n");
		close(sock_fd);
		return(-1);
	}

	// compress attack
	logmsg(LOG_DEBUG, 1, "SubmitNebula - Compressing attack data.\n");
	cbuf_len = attack->a_conn.payload.size + (attack->a_conn.payload.size * 0.002) + 12;
	if ((cbuf = calloc(1, cbuf_len)) == NULL) {
		logmsg(LOG_ERR, 1, "SubmitNebula Error - Unable to allocate memory: %m.\n");
		return(-1);
	}
	switch (compress(cbuf, (unsigned long *)&cbuf_len, attack->a_conn.payload.data, attack->a_conn.payload.size)) {
	case Z_OK:
		break;
	case Z_MEM_ERROR:
		logmsg(LOG_ERR, 1, "SubmitNebula Error - Cannot compress attack data: Out of memory.\n");
		return(-1);
	case Z_BUF_ERROR:
		logmsg(LOG_ERR, 1, "SubmitNebula Error - Cannot compress attack data: Output buffer too small.\n");
		return(-1);
	default:
		logmsg(LOG_ERR, 1, "SubmitNebula Error - Cannot compress attack data: Unknown error.\n");
		return(-1);
	}
	logmsg(LOG_DEBUG, 1, "SubmitNebula - Compressed data has %u bytes.\n", cbuf_len);

	// send length of compressed attack
	if (write(sock_fd, &cbuf_len, 4) == -1) {
		logmsg(LOG_ERR, 1, "SubmitNebula Error - Writing to socket failed: %m.\n");
		close(sock_fd);
		return(-1);
	}

	// send compressed attack
	if (write(sock_fd, cbuf, cbuf_len) == -1) {
		logmsg(LOG_ERR, 1, "SubmitNebula Error - Writing to socket failed: %m.\n");
		close(sock_fd);
		return(-1);
	}

	// wait for OK
	logmsg(LOG_DEBUG, 1, "SubmitNebula - Attack sent, waiting for OK.\n");
	if (!read_line(sock_fd, (char *) response, 8, 10)) {
		logmsg(LOG_WARN, 1, "SubmitNebula Warning - Nebula server did not respond within 10 seconds.\n");
	} else if (strlen((char *) response) != 2 || strncmp((char *) response, "OK", 2) != 0)
		logmsg(LOG_WARN, 1, "SubmitNebula - Invalid response from Nebula server.\n");

	close(sock_fd);
	free(cbuf);

	logmsg(LOG_NOISY, 1, "SubmitNebula - Submission complete.\n");

	return(0);
}
