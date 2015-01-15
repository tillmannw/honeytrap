/* htm_cspm.c
 * Copyright (C) 2007-2015 Tillmann Werner <tillmann.werner@gmx.de>
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
 *   This honeytrap module tries to identifies common shellcodes
 *   by performing a pattern matching procedure originally developed
 *   by Paul Baecher and Markus Koetter for nepenthes.
 */

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <attack.h>
#include <conftree.h>
#include <honeytrap.h>
#include <logging.h>
#include <plughook.h>
#include <readconf.h>
#include <util.h>

#include "htm_cspm.h"
#include "sc_parser.h"
#include "signature_parser.h"

const char module_name[]="cspm";
const char module_version[]="1.0.1";

char *sc_sigfile = NULL;

static const char *config_keywords[] = {
	"shellcode_sigfile"
};


void plugin_config(void) {
	register_plugin_confopts(module_name, config_keywords, sizeof(config_keywords)/sizeof(char *));
	if (process_conftree(config_tree, config_tree, plugin_process_confopts, NULL) == NULL) {
		fprintf(stderr, "  Error - Unable to process configuration tree for plugin %s.\n", module_name);
		exit(EXIT_FAILURE);
	}
	if (load_shellcodes() == 0) {
		logmsg(LOG_ERR, 1, "Error - Unable to load shellcode signatures.\n");
		exit(EXIT_FAILURE);
	}
	return;
}

void plugin_init(void) {
	plugin_register_hooks();
	return;
}

void plugin_unload(void) {
	unhook(PPRIO_POSTPROC, module_name, "sc_match");
	return;
}

void plugin_register_hooks(void) {
	logmsg(LOG_DEBUG, 1, "    Plugin %s: Registering hooks.\n", module_name);
	add_attack_func_to_list(PPRIO_POSTPROC, module_name, "sc_match", (void *) sc_match);

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

		if OPT_IS("shellcode_sigfile") {
			sc_sigfile = value;
		} else {
			fprintf(stderr, "  Error - Invalid configuration option for plugin %s: %s\n", module_name, node->keyword);
			exit(EXIT_FAILURE);
		}
	}
	return(node);
}

int load_shellcodes(void) {
	struct sc_shellcode *sc;
	int num_of_shellcodes = 0, load_success = 1;

	if ((sc = (struct sc_shellcode *) sc_parse_file(sc_sigfile)) == NULL) {
		logmsg(LOG_ERR, 1, "Error - Could not parse shellcodes from file %s\n", sc_sigfile);
		logmsg(LOG_ERR, 1, "Error %s\n", (char *) sc_get_error());
		return(0);
	}

	for (sclist = sc; sc && load_success == 1; sc = sc->next, num_of_shellcodes++)
		if (sc->name && (prepare_sc(sc) != 0)) load_success = 0;

	logmsg(LOG_DEBUG, 0, "    %d shellcode signatures prepared.\n", num_of_shellcodes);
	return(1);
}

int sc_match(Attack *attack) {
	uint32_t rhost, lhost;

	/* no data - nothing todo */
	if (!attack->a_conn.payload.size) {
		logmsg(LOG_DEBUG, 1, "No data received, won't start shellcode matching.\n");
		return(0);
	}

	rhost = (uint32_t) attack->a_conn.r_addr;
	lhost = (uint32_t) attack->a_conn.l_addr;
	
	if (eval_sc_mgr(attack->a_conn.payload.data, attack->a_conn.payload.size,
			rhost, attack->a_conn.r_port,
			lhost, attack->a_conn.l_port) == SCH_DONE) {
		logmsg(LOG_DEBUG, 1, "Shellcode matching is done.\n");
	}

	return(1);
}
