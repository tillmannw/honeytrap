/* htm_submitNebula.c
 * Copyright (C) 2008-2015 Tillmann Werner <tillmann.werner@gmx.de>
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
#include <nebula.h>
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
#include <plughook.h>
#include <readconf.h>
#include <signals.h>
#include <sock.h>
#include <tcpip.h>
#include <util.h>

#include "htm_submitNebula.h"


const char module_name[]="submitNebula";
const char module_version[]="1.0.1";

static const char *config_keywords[] = {
	"host",
	"port",
	"secret"
};

nebula *n;


void plugin_config(void) {
	register_plugin_confopts(module_name, config_keywords, sizeof(config_keywords)/sizeof(char *));
	if (process_conftree(config_tree, config_tree, plugin_process_confopts, NULL) == NULL) {
		fprintf(stderr, "  Error - Unable to process configuration tree for plugin %s.\n", module_name);
		exit(EXIT_FAILURE);
	}
	return;
}

void plugin_init(void) {
	if ((n = nebula_new()) == NULL) {
		fprintf(stderr, "Error - Unable to initialize nebula handle: %s.\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (nebula_init(n) == 0) {
		fprintf(stderr, "  Error - Could not initialize nebula instance: %s.\n", nebula_strerr(n));
		exit(EXIT_FAILURE);
	}

	plugin_register_hooks();

	return;
}

void plugin_unload(void) {
	nebula_cleanup(n);
	unhook(PPRIO_SAVEDATA, module_name, "submit_nebula");
	return;
}

void plugin_register_hooks(void) {
	logmsg(LOG_DEBUG, 1, "    Plugin %s: Registering hooks.\n", module_name);
	add_attack_func_to_list(PPRIO_SAVEDATA, module_name, "submit_nebula", (void *) submit_nebula);

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
			struct hostent *host;

			if ((host = gethostbyname(value)) == NULL) {
				fprintf(stderr, "  Error - Unable to resolve %s: %s.\n", value, strerror(errno));
				exit(EXIT_FAILURE);
			}
			n->server.sin_addr = *(struct in_addr*)host->h_addr;
		} else if OPT_IS("port") {
			if (value) n->server.sin_port = htons((u_int16_t) strtoull(value, NULL, 10));
		} else if OPT_IS("secret") {
			if ((n->secret = strdup(value)) == NULL) {
				fprintf(stderr, "  Error - Unable to allocate memory: %s.\n", nebula_strerr(n));
				exit(EXIT_FAILURE);
			}
		} else {
			fprintf(stderr, "  Error - Invalid configuration option for plugin %s: %s\n", module_name, node->keyword);
			exit(EXIT_FAILURE);
		}
	}
	return(node);
}


// submit attack to a Nebula server
int submit_nebula(Attack *attack) {
	// no data - nothing to do
	if ((attack->a_conn.payload.size == 0) || (attack->a_conn.payload.data == NULL)) {
		logmsg(LOG_DEBUG, 1, "SubmitNebula - No data received.\n");
		return(0);
	}

	logmsg(LOG_INFO, 1, "SubmitNebula - Submittint attack to nebula server.\n");

	// connect to nebula server and submit attack
	if (nebula_connect(n, n->server.sin_addr, ntohs(n->server.sin_port), 0) == 0) {
		logmsg(LOG_ERR, 1, "SubmitNebula Error - Could not connect to nebula server: %s.\n", nebula_strerr(n));
		exit(EXIT_FAILURE);
	}
	if (nebula_send(n, attack->a_conn.protocol, attack->a_conn.l_port, attack->a_conn.payload.data, attack->a_conn.payload.size) == 0)
		logmsg(LOG_ERR, 1, "SubmitNebula Error - File submission failed: %s.\n", nebula_strerr(n));
	if (nebula_disconnect(n) == 0)
		logmsg(LOG_ERR, 1, "SubmitNebula Error - Could not disconnect from nebula server: %s.\n", nebula_strerr(n));

	logmsg(LOG_NOISY, 1, "SubmitNebula - Submission complete.\n");

	return 0;
}
