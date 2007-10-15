/* htm_submitMwserv.c
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
 * Description:
 *   still to come...
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <strings.h>
#include <stdio.h>

#include <conftree.h>
#include <honeytrap.h>
#include <logging.h>
#include <plughook.h>
#include <readconf.h>

#include "htm_submitMwserv.h"

const char module_name[]="submitMwserv";
const char module_version[]="0.1.0";

static const char *config_keywords[] = {
	"host",
	"port",
	"sensor"
};

const char	*mwserv_host;
const char	*sensor;
u_int32_t	mwserv_port;


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
	unhook(PPRIO_SAVEDATA, module_name, "submit_mwserv");
	return;
}

void plugin_register_hooks(void) {
	DEBUG_FPRINTF(stdout, "    Plugin %s: Registering hooks.\n", module_name);
	add_attack_func_to_list(PPRIO_SAVEDATA, module_name, "submit_mwserv", (void *) submit_mwserv);

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
			mwserv_host = value;
		} else if OPT_IS("port") {
			mwserv_port = atoi(value);
		} else if OPT_IS("sensor") {
			sensor = value;
		} else {
			fprintf(stderr, "  Error - Invalid configuration option for plugin %s: %s\n", module_name, node->keyword);
			exit(EXIT_FAILURE);
		}
	}
	return(node);
}

int submit_mwserv(Attack *attack) {


	/* no data - nothing todo */
	if ((attack->a_conn.payload.size == 0) || (attack->a_conn.payload.data == NULL)) {
		logmsg(LOG_DEBUG, 1, "Base64 decoder - No data received, nothing to decode.\n");
		return(0);
	}

	// logmsg(LOG_DEBUG, 1, "SubmitMWserv - Submitting sample(s) to malware server.\n");

	/* do libcurl stuff here */

	return(1);
}
