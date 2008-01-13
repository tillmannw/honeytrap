/* htm_httpDownload.c
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
 *   This honeytrap module parses an attack string for http urls.
 *   Matches are passed to an external program, i.e. wget.
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

#include <honeytrap.h>
#include <logging.h>
#include <md5.h>
#include <plughook.h>
#include <readconf.h>
#include <signals.h>
#include <sock.h>
#include <tcpip.h>
#include <util.h>

#include "htm_httpDownload.h"

const char module_name[]="httpDownload";
const char module_version[]="0.0.2";

static const char *config_keywords[] = {
	"http_program",
	"http_options",
	"download_dir"
};

const char *http_program;
const char *http_options;
const char *download_dir;


void plugin_init(void) {
	plugin_register_hooks();
	plugin_register_confopts();
	if (process_conftree(config_tree, config_tree, plugin_process_confopts, NULL) == NULL) {
		fprintf(stderr, "  Error - Unable to process configuration tree for plugin %s.\n", module_name);
		exit(EXIT_FAILURE);
	}
	return;
}


void plugin_unload(void) {
	unhook(PPRIO_POSTPROC, module_name, "cmd_parse_for_http_url");
	return;
}

void plugin_register_hooks(void) {
	DEBUG_FPRINTF(stdout, "    Plugin %s: Registering hooks.\n", module_name);
	add_attack_func_to_list(PPRIO_POSTPROC, module_name, "cmd_parse_for_http_url", (void *) cmd_parse_for_http_url);

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

	DEBUG_FPRINTF(stdout, "    Plugin %s: Registering hooks.\n", module_name);
	/* build tree of allowed configuration keywords */
	for (i=0; i<sizeof(config_keywords)/sizeof(char *); i++) {

		/* assemble full config option path */
		if ((confopt = malloc(strlen(full_name)+strlen(config_keywords[i])+2)) == NULL) {
			fprintf(stderr, "  Error - Unable to allocate memory: %s.\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
		memset(confopt, 0, strlen(full_name)+strlen(config_keywords[i])+2);
		strcat(confopt, full_name);
		strcat(confopt, ".");
		strcat(confopt, config_keywords[i]);

		/* add config option to tree */
		if (add_keyword(&config_keywords_tree, confopt, NULL, 0) == NULL) {
			fprintf(stderr, "  Error - Unable to add configuration keyword to tree.\n");
			exit(EXIT_FAILURE);
		}	
		free(confopt);
	}
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

		if OPT_IS("http_program") {
			http_program = value;
		} else if OPT_IS("http_options") {
			http_options = value;
		} else if OPT_IS("download_dir") {
			download_dir = value;
		} else {
			fprintf(stderr, "  Error - Invalid configuration option for plugin %s: %s\n", module_name, node->keyword);
			exit(EXIT_FAILURE);
		}
	}
	return(node);
}

int cmd_parse_for_http_url(Attack *attack) {
	int i = 0, j = 0;
	FILE *f = NULL;
	char *string_for_processing, *start, *end, *cmd;

	string_for_processing	= NULL;
	start			= NULL;
	end			= NULL;
	cmd			= NULL;

	/* no data - nothing todo */
	if ((attack->a_conn.payload.size == 0) || (attack->a_conn.payload.data == NULL)) {
		logmsg(LOG_DEBUG, 1, "FTP download - No data received, nothing to download.\n");
		return(0);
	}

	logmsg(LOG_DEBUG, 1, "HTTP download - Parsing attack string (%d bytes) for URLs.\n", attack->a_conn.payload.size);

	string_for_processing = (char *) malloc(attack->a_conn.payload.size + 1);
	memcpy(string_for_processing, attack->a_conn.payload.data, attack->a_conn.payload.size);
	string_for_processing[attack->a_conn.payload.size] = 0;
	
	for (i=0; i<attack->a_conn.payload.size; i++) {
		if ((attack->a_conn.payload.size-i >= 7)
			&& (memcmp(string_for_processing+i, "http://", 7) == 0)) {

			start = string_for_processing+i;

			/* 0-terminate URL */
			for (end = start, j=0; j<strlen(start) && end[0]; end = &start[j++]) {
				if (isspace(end[0])) end[0] = 0;
				else if (!isprint(end[0])) end[0] = 0;
			}
			if (isspace(end[0])) end[0] = 0;

			logmsg(LOG_DEBUG, 1, "HTP download - URL found: '%s'\n", start);

			/* change into download directory */
			if (chdir(download_dir) == -1) {
				logmsg(LOG_ERR, 1, "HTTP download error - Unable to change into download directory %s: %m.\n", download_dir);
				return(-1);
			}

			/* assemble wget download command and execute it */
			asprintf(&cmd, "%s %s %s", http_program, http_options, start);
			logmsg(LOG_DEBUG, 1, "HTTP download - Calling '%s'.\n", cmd);
			if ((f = popen(cmd, "r")) == NULL) {
				logmsg(LOG_ERR, 1, "HTTP download error - Cannot call download command: %m.\n");
				return(0);
			}
			pclose(f);
			free(cmd);

			i += strlen(start);
			logmsg(LOG_INFO, 1, "HTTP download - %s successfully downloaded to %s.\n", start, download_dir);
		}
	}
	if (!start) logmsg(LOG_DEBUG, 1, "HTTP download - No URLs found.\n");
	return(0);
}
