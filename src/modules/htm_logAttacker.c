/* htm_logAttacker.c
 * Copyright (C) 2011-2015 Tillmann Werner <tillmann.werner@gmx.de>
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
 *   This module assumes that an input is xor-encoded and performs a
 *   matching of known patterns in order to extract the key and decode the
 *   data. Decoded attack strings are then further processed as virtual
 *   attacks. An example application is getting URLs from self-modifying
 *   shellcode without having to run any kind of emulation.
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>

#include <honeytrap.h>
#include <logging.h>
#include <plughook.h>
#include <readconf.h>


const char module_name[]="logattacker";
const char module_version[]="1.0.2";

static const char *config_keywords[] = {
	"logfile",
};

const char *logfile;
FILE *f;


int logattacker(Attack *a) {
	struct tm *tm;
	struct timeval tv;
	char tstr[20];
	char shost[16], dhost[16];
	struct protoent *pent;
    
    if (a->virtual) return 0; // do not log virtual attacks


	logmsg(LOG_DEBUG, 1, "logAttacker: logging attacker information\n");

	if (gettimeofday(&tv, NULL) == -1) {
		logmsg(LOG_ERR, 1, "logAttacker error - Could not get system time.\n");
		return -1;
	}

	tm = gmtime(&tv.tv_sec);
	if (strftime(tstr, 20, "%F %H:%M:%S", tm) == 0) {
		logmsg(LOG_ERR, 1, "logAttacker error - Unable to create time stamp.\n");
		return -1;
	}

	if ((inet_ntop(AF_INET, &a->a_conn.r_addr, shost, 16) == NULL) ||
	    (inet_ntop(AF_INET, &a->a_conn.l_addr, dhost, 16) == NULL)) {
		logmsg(LOG_ERR, 1, "logAttacker error - Unable to convert IP address into string.\n");
		return -1;
	}

	if ((pent = getprotobynumber(a->a_conn.protocol)) == NULL) {
		logmsg(LOG_ERR, 1, "logAttacker error - Unable to determine name for protocol %d.\n", a->a_conn.protocol);
		return -1;
	}

	if (fprintf(f, "[%s:%lu GMT] %s %s:%d -> %s:%d %s %s (%u bytes)\n",
		tstr, tv.tv_usec, pent->p_name, shost, a->a_conn.r_port, dhost, a->a_conn.l_port, a->a_conn.payload.md5sum, a->a_conn.payload.sha512sum, a->a_conn.payload.size) < 0) {
		logmsg(LOG_ERR, 1, "logAttacker error - Could not write to log file: %s.\n", strerror(errno));
		return -1;
	}

	return 0;
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

		if OPT_IS("logfile") {
			logfile = value;
		} else {
			fprintf(stderr, "  Error - Invalid configuration option for plugin %s: %s\n", module_name, node->keyword);
			exit(EXIT_FAILURE);
		}
	}
	return(node);
}

void plugin_register_hooks(void) {
	logmsg(LOG_DEBUG, 1, "    Plugin %s: Registering hooks.\n", module_name);
	add_attack_func_to_list(PPRIO_PREPROC, module_name, "logattacker", (void *) logattacker);

	return;
}

void plugin_config(void) {
	register_plugin_confopts(module_name, config_keywords, sizeof(config_keywords)/sizeof(char *));
	if (process_conftree(config_tree, config_tree, plugin_process_confopts, NULL) == NULL) {
		fprintf(stderr, "  Error - Unable to process configuration tree for plugin %s.\n", module_name);
		exit(EXIT_FAILURE);
	}
	return;
}

void plugin_init(void) {
	mode_t prevmode;

	// open log file
	logmsg(LOG_DEBUG, 1, "    Plugin %s: Opening log file %s.\n", module_name, logfile);

	prevmode = umask(S_IWGRP | S_IWOTH);
	if ((f = fopen(logfile, "a")) == NULL) {
		fprintf(stderr, "  Error - Unable to open attacker log file: %s.\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	umask(prevmode);

	plugin_register_hooks();

	return;
}

void plugin_unload(void) {
	unhook(PPRIO_PREPROC, module_name, "logattacker");

	// close log file
	fclose(f);

	return;
}
