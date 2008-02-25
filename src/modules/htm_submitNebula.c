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
#include <sha512.h>
#include <signals.h>
#include <sock.h>
#include <tcpip.h>
#include <util.h>

#include "htm_submitNebula.h"


const char module_name[]="submitNebula";
const char module_version[]="0.1.1";

static const char *config_keywords[] = {
	"host",
	"port",
	"secret"
};

const char	*nebula_secret;
const char	*nebula_host;
u_int16_t	nebula_port;


// hmac stuff 
#define HMAC_HASH_SIZE	128	// for sha512
#define HMAC_BLOCK_SIZE	256	// for sha512
#define IPAD_VAL	0x36
#define OPAD_VAL	0x5C    

u_char		k[HMAC_BLOCK_SIZE];
u_char		k_ipad[HMAC_BLOCK_SIZE];
u_char		k_opad[HMAC_BLOCK_SIZE];



void plugin_init(void) {
	int i;

	plugin_register_hooks();
	register_plugin_confopts(module_name, config_keywords, sizeof(config_keywords)/sizeof(char *));
	if (process_conftree(config_tree, config_tree, plugin_process_confopts, NULL) == NULL) {
		fprintf(stderr, "  Error - Unable to process configuration tree for plugin %s.\n", module_name);
		exit(EXIT_FAILURE);
	}

	// initialize HMAC pads
	memset(k_ipad, IPAD_VAL, HMAC_BLOCK_SIZE);
	memset(k_opad, OPAD_VAL, HMAC_BLOCK_SIZE);
	if (nebula_secret) for (i=0; i<strlen(nebula_secret); i++) {
		k_ipad[i] ^= nebula_secret[i];
		k_opad[i] ^= nebula_secret[i];
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


// calculate HMAC
char *hmac(u_char **msg, ssize_t len) {
	u_char	*inner, *outer;

	// append inner padding to message
	if ((*msg = realloc(*msg, len+HMAC_BLOCK_SIZE)) == NULL) {
		logmsg(LOG_ERR, 1, "SubmitNebula Error - Unable to allocate memory: %m.\n");
		return(NULL);
	}
	memcpy(*msg+len, k_ipad, HMAC_BLOCK_SIZE);

	// compute inner hash
	if ((inner = (u_char *) mem_sha512sum(*msg, len+HMAC_BLOCK_SIZE)) == NULL) {
		logmsg(LOG_ERR, 1, "SubmitNebula Error - Unable to compute inner HMAC SHA512 hash.\n");
		return(NULL);
	}

	// append outer padding to iner hash
	if ((inner = realloc(inner, HMAC_HASH_SIZE+HMAC_BLOCK_SIZE)) == NULL) {
		logmsg(LOG_ERR, 1, "SubmitNebula Error - Unable to allocate memory: %m.\n");
		free(inner);
		return(NULL);
	}
	memcpy(&inner[HMAC_HASH_SIZE], k_opad, HMAC_BLOCK_SIZE);

	// compute outer hash
	if ((outer = (u_char *) mem_sha512sum(inner, HMAC_HASH_SIZE+HMAC_BLOCK_SIZE)) == NULL)
		logmsg(LOG_ERR, 1, "SubmitNebula Error - Unable to compute outer HMAC SHA512 hash.\n");

	free(inner);
	return((char *) outer);
}


// submit attack to a Nebula server
int submit_nebula(Attack *attack) {
	struct hostent		*host;
	unsigned long		cbuf_len;
	u_char			*cbuf, response[9];
	u_int32_t		nonce, len;
	u_int16_t		hmac_len, hmac_port;
	struct sockaddr_in	sock;
	int			sock_fd, bytes_read, total_bytes;
	char			*sha512sum;

	struct timeval		r_timeout;
	fd_set			rfds;

	cbuf_len		= 0;
	cbuf			= NULL;
	host			= NULL;

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



	// get nonce from server
	FD_ZERO(&rfds);
	FD_SET(sigpipe[0], &rfds);
	FD_SET(sock_fd, &rfds);

	r_timeout.tv_sec = 10;
	r_timeout.tv_usec = 0;

	/* wait for incoming data, close connection on timeout */
	logmsg(LOG_DEBUG, 1, "SubmitNebula - Waiting for nonce, timeout is %d seconds.\n",
		(u_int16_t) r_timeout.tv_sec);

	switch (select(MAX(sigpipe[0], sock_fd) + 1, &rfds, NULL, NULL, &r_timeout)) {
	case -1:
		if (errno == EINTR) {
			if (check_sigpipe() == -1) exit(EXIT_FAILURE);
			break;
		}
		logmsg(LOG_ERR, 1, "SubmitNebula Error - Select failed: %m.\n");
		close(sock_fd);
		return(-1);
	case 0:
		logmsg(LOG_ERR, 1, "SubmitNebula Warning - Did not receive nonce within %u seconds.\n", (unsigned int) r_timeout.tv_sec);
		close(sock_fd);
		return(-1);
	default:
		if (FD_ISSET(sigpipe[0], &rfds) && (check_sigpipe() == -1)) exit(EXIT_FAILURE);
		if (FD_ISSET(sock_fd, &rfds)) {
			logmsg(LOG_DEBUG, 1, "SubmitNebula - Reading nonce.\n");
			for (bytes_read = 1, total_bytes = 0; bytes_read && total_bytes < 4; total_bytes += bytes_read)
				bytes_read = read(sock_fd, &nonce+total_bytes, 4);

			if (bytes_read < 0) {
				logmsg(LOG_ERR, 1, "SubmitNebula Error - Unable to read from socket: %m.\n");
				close(sock_fd);
				return(-1);
			}
			nonce = ntohl(nonce);
			logmsg(LOG_DEBUG, 1, "SubmitNebula - Nonce received.\n");
		}
	}


	// hash secret with nonce
	if ((cbuf = malloc(strlen(nebula_secret)+4)) == NULL) {
		logmsg(LOG_ERR, 1, "SubmitNebula Error - Unable to allocate memory: %m.\n");
		close(sock_fd);
		return(-1);
	}
	memcpy(cbuf, nebula_secret, strlen(nebula_secret));
	memcpy(cbuf+strlen(nebula_secret), &nonce, 4);
	if ((sha512sum = mem_sha512sum(cbuf, strlen(nebula_secret)+4)) == NULL) {
		logmsg(LOG_ERR, 1, "SubmitNebula Error - Unable to hash secret.\n");
		close(sock_fd);
		return(-1);
	}
	free(cbuf);

	// send hashed secret
	if (write(sock_fd, sha512sum, 128) == -1) {
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


	if (!read_line(sock_fd, (char *) &response, 9, 10)) {
		logmsg(LOG_WARN, 1, "SubmitNebula Warning - Nebula server did not respond within 10 seconds, skipping submission.\n");
		close(sock_fd);
		return(0);
	}
	if (strncmp((char *) response, "KNOWN", 5) == 0) {
		logmsg(LOG_WARN, 1, "SubmitNebula - Attack hash is already known to the server, skipping submission.\n");
		close(sock_fd);
		return(0);
	}
	if (strncmp((char *) response, "UNKNOWN", 7)) {
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

	// send port
	hmac_port = htons(attack->a_conn.l_port);
	if (write(sock_fd, &(hmac_port), 2) == -1) {
		logmsg(LOG_ERR, 1, "SubmitNebula Error - Writing to socket failed: %m.\n");
		close(sock_fd);
		return(-1);
	}

	// send length of uncompressed attack
	len = htonl(attack->a_conn.payload.size);
	if (write(sock_fd, &(len), 4) == -1) {
		logmsg(LOG_ERR, 1, "SubmitNebula Error - Writing to socket failed: %m.\n");
		close(sock_fd);
		return(-1);
	}

	// compress attack
	logmsg(LOG_DEBUG, 1, "SubmitNebula - Compressing attack data.\n");
	cbuf_len = (attack->a_conn.payload.size * 1.1) + 12;
	if ((cbuf = calloc(1, cbuf_len)) == NULL) {
		logmsg(LOG_ERR, 1, "SubmitNebula Error - Unable to allocate memory: %m.\n");
		return(-1);
	}
	switch (compress(cbuf, &cbuf_len, attack->a_conn.payload.data, attack->a_conn.payload.size)) {
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
	logmsg(LOG_DEBUG, 1, "SubmitNebula - Compressed data has %lu bytes.\n", cbuf_len);

	// send length of compressed attack
	len = htonl(cbuf_len);
	if (write(sock_fd, &len, 4) == -1) {
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

	// append protocol and port to cattack for HMAC calculation
	if ((cbuf = realloc(cbuf, cbuf_len+3)) == NULL) {
		logmsg(LOG_ERR, 1, "SubmitNebula Error - Unable to allocate memory: %m.\n");
		close(sock_fd);
		return(-1);
	}
	memcpy(cbuf+cbuf_len, &attack->a_conn.protocol, 1);
	memcpy(cbuf+cbuf_len+1, &hmac_port, 2);

	if ((sha512sum = hmac(&cbuf, cbuf_len+3)) == NULL) {
		free(cbuf);
		close(sock_fd);
		return(-1);
	}
	free(cbuf);

	// send length of HMAC
	hmac_len = ntohs(strlen(sha512sum));
	if (write(sock_fd, &hmac_len, sizeof(hmac_len)) == -1) {
		logmsg(LOG_ERR, 1, "SubmitNebula Error - Writing to socket failed: %m.\n");
		close(sock_fd);
		return(-1);
	}

	// send HMAC
	if (write(sock_fd, sha512sum, strlen(sha512sum)) == -1) {
		logmsg(LOG_ERR, 1, "SubmitNebula Error - Writing to socket failed: %m.\n");
		close(sock_fd);
		return(-1);
	}
	free(sha512sum);

	// wait for OK
	logmsg(LOG_DEBUG, 1, "SubmitNebula - Attack sent, waiting for OK.\n");
	if (!read_line(sock_fd, (char *) response, 9, 10)) {
		logmsg(LOG_WARN, 1, "SubmitNebula Warning - Nebula server did not respond within 10 seconds.\n");
	} else if (strlen((char *) response) != 2 || strncmp((char *) response, "OK", 2) != 0)
		logmsg(LOG_WARN, 1, "SubmitNebula - Invalid response from Nebula server.\n");

	close(sock_fd);

	logmsg(LOG_NOISY, 1, "SubmitNebula - Submission complete.\n");

	return(0);
}
