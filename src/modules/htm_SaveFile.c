/* htm_SaveFile.c
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
 *   This honeytrap module dumps incoming traffic from incoming
 *   connections to a file.
 *   Also, all malware/sample entries attached to an attack record
 *   are dumped into a download directory.
 */

#define _GNU_SOURCE 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <time.h>

#include <attack.h>
#include <conftree.h>
#include <honeytrap.h>
#include <logging.h>
#include <md5.h>
#include <plughook.h>
#include <readconf.h>
#include <tcpip.h>

#include "htm_SaveFile.h"

const char module_name[]="SaveFile";
const char module_version[]="1.0.1";

static const char *config_keywords[] = {
	"attacks_dir",
	"downloads_dir"
};

const char *attacks_dir;
const char *downloads_dir;


void plugin_config(void) {
	register_plugin_confopts(module_name, config_keywords, sizeof(config_keywords)/sizeof(char *));
	if (process_conftree(config_tree, config_tree, plugin_process_confopts, NULL) == NULL) {
		fprintf(stderr, "  Error - Unable to process configuration tree for plugin %s.\n", module_name);
		exit(EXIT_FAILURE);
	}
	return;
}

void plugin_init(void) {
	plugin_register_hooks();
	return;
}

void plugin_unload(void) {
	unhook(PPRIO_SAVEDATA, module_name, "save_to_file");
	return;
}

void plugin_register_hooks(void) {
	logmsg(LOG_DEBUG, 1, "    Plugin %s: Registering hooks.\n", module_name);
	add_attack_func_to_list(PPRIO_SAVEDATA, module_name, "save_to_file", (void *) save_to_file);

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

		if OPT_IS("attacks_dir") {
			attacks_dir = value;
		} else if OPT_IS("downloads_dir") {
			downloads_dir = value;
		} else {
			fprintf(stderr, "  Error - Invalid configuration option for plugin %s: %s\n", module_name, node->keyword);
			exit(EXIT_FAILURE);
		}
	}
	return(node);
}

int save_to_file(Attack *attack) {
	struct tm *file_time;
	time_t loc_time;
	char *filename, *mwfilename, *proto_str;
	int i, dumpfile_fd;

	filename	= NULL;
	mwfilename	= NULL;
	proto_str	= NULL;

	/* no data - nothing todo */
	if ((attack->a_conn.payload.size == 0) || (attack->a_conn.payload.data == NULL)) {
		logmsg(LOG_DEBUG, 1, "SaveFile - No data received, no need for dumpfile creation.\n");
		return(0);
	}

	logmsg(LOG_DEBUG, 1, "SaveFile - Dumping attack string into file.\n");

	/* create filename */
	if (attack->a_conn.protocol == TCP) proto_str = "tcp";
	else if (attack->a_conn.protocol == UDP) proto_str = "udp";
	else if (attack->a_conn.protocol == RAW) proto_str = "raw";
	else {
		logmsg(LOG_ERR, 1, "SaveFile error - Protocol %u is not supported.\n", attack->a_conn.protocol);
		return(-1);
	}

	/* assemble filename */
	loc_time = time(NULL);
	if((file_time = localtime(&loc_time)) == NULL) {
		logmsg(LOG_WARN, 1, "SaveFile warning - Unable to get local time for filename.\n");
		if (asprintf(&filename, "%s/from_port_%u-%s_%u", attacks_dir, attack->a_conn.l_port, proto_str, getpid()) == -1) {
			logmsg(LOG_ERR, 1, "SaveFile error - Unable to create filename: %m.\n");
			return(-1);
		}
	} else {
		if (asprintf(&filename, "%s/from_port_%u-%s_%u_%04d-%02d-%02d", attacks_dir, attack->a_conn.l_port, proto_str,
			getpid(), file_time->tm_year+1900, file_time->tm_mon+1, file_time->tm_mday) == -1) {
			logmsg(LOG_ERR, 1, "SaveFile error - Unable to create filename: %m.\n");
			return(-1);
		}
	}

	/* open file and set access rights */
	if ((dumpfile_fd = open(filename, O_WRONLY | O_CREAT | O_EXCL, 644)) < 0) {
		logmsg(LOG_ERR, 1, "SaveFile error - Unable to save attack string in attacks directory: %s\n", strerror(errno));
		return(-1);
	}
	if (chmod(filename, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) != 0)
		logmsg(LOG_WARN, 1, "SaveFile warning - Unable to set proper acces rights\n");


	/* write data to file */
	if (write(dumpfile_fd, attack->a_conn.payload.data, attack->a_conn.payload.size) != attack->a_conn.payload.size) {
		logmsg(LOG_ERR, 1, "SaveFile error - Unable to write attack string into file: %s\n", strerror(errno));
		close(dumpfile_fd);
		return(-1);
	}
	close(dumpfile_fd);
	logmsg(LOG_DEBUG, 1, "SaveFile - Attack string saved as %s.\n", filename);

	/* save malware */
	for (i=0; i<attack->dl_count; i++) {
		logmsg(LOG_DEBUG, 1, "SaveFile - Saving %d attached malware sample(s).\n", attack->dl_count);
		/* save file */
		if (attack->download[i].filename) {
			if (asprintf(&mwfilename, "%s/%s-%s", downloads_dir, mem_md5sum(attack->download[i].dl_payload.data,
				attack->download[i].dl_payload.size), attack->download[i].filename) == -1) {
				logmsg(LOG_ERR, 1, "SaveFile error - Unable to create filename: %s.\n", strerror(errno));
				return(-1);
			}
		} else {
			if (asprintf(&mwfilename, "%s/%s", downloads_dir, mem_md5sum(attack->download[i].dl_payload.data,
				attack->download[i].dl_payload.size)) == -1) {
				logmsg(LOG_ERR, 1, "SaveFile error - Unable to create filename: %s.\n", strerror(errno));
				return(-1);
			}
		}
		logmsg(LOG_DEBUG, 1, "SaveFile - Malware sample dumpfile name is %s\n", mwfilename);
		if (((dumpfile_fd = open(mwfilename, O_WRONLY | O_CREAT | O_EXCL, 644)) < 0) ||
		    (fchmod(dumpfile_fd, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) != 0)) {
			logmsg(LOG_WARN, 1, "SaveFile error - Unable to save malware sample dumpfile %s: %s.\n", mwfilename,
				strerror(errno));
			close(dumpfile_fd);
			return(-1);
		}
		if (write(dumpfile_fd,
			attack->download[i].dl_payload.data,
			attack->download[i].dl_payload.size) != attack->download[i].dl_payload.size) { 
			logmsg(LOG_ERR, 1, "SaveFile error - Unable to save malware sample dumpfile: %s\n",
				strerror(errno));
			close(dumpfile_fd);
			return(-1);
		}
		close(dumpfile_fd);
		if (attack->download[i].filename)
			logmsg(LOG_NOTICE, 1, "SaveFile - Malware sample dumpfile %s saved.\n", attack->download[i].filename);
		else
			logmsg(LOG_NOTICE, 1, "SaveFile - Malware sample dumpfile saved.\n");
	}

	return(0);
}
