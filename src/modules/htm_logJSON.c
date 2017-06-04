/* htm_logJSON.c
 * Copyright (C) 2016 Andrea De Pasquale <andrea@de-pasquale.name>
 *
 * This file is free software; as a special exception the author gives
 * unlimited permission to copy and/or distribute it, with or without
 * modifications, as long as this notice is preserved.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
 * implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
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
#include <json-c/json.h>

#include <honeytrap.h>
#include <logging.h>
#include <plughook.h>
#include <readconf.h>


const char module_name[]="logjson";
const char module_version[]="1.1.0";

static const char *config_keywords[] = {
	"logfile",
};

const char *logfile;
FILE *f;


int convert_payload_to_json(struct s_payload *sp, json_object *jp) {
	char *data_hex;
	int i;

	// 2 bytes for each original byte, plus one byte for the null terminator
	if ((data_hex = malloc(2 * sp->size + 1)) == NULL) {
		logmsg(LOG_ERR, 1, "logJSON: unable to allocate memory for payload conversion. %s.\n", strerror(errno));
		return -1;
	}

	memset(data_hex, 0, 2 * sp->size + 1);

	// convert binary data to hex
	for (i = 0; i < sp->size; ++i) {
		sprintf(&data_hex[2*i], "%02x", sp->data[i]);
	}

	json_object_object_add(jp, "md5_hash", json_object_new_string(sp->md5sum));
	json_object_object_add(jp, "sha512_hash", json_object_new_string(sp->sha512sum));
	json_object_object_add(jp, "length", json_object_new_int(sp->size));
	json_object_object_add(jp, "data_hex", json_object_new_string(data_hex));

	free(data_hex);

	return 0;
}

int convert_download_to_json(struct s_download *sd, json_object *jd) {
	json_object *j_payload;
	struct protoent *pent;
	char rhost[16], lhost[16];

	if ((pent = getprotobynumber(sd->protocol)) == NULL) {
		logmsg(LOG_ERR, 1, "logJSON: unable to determine name for protocol %d.\n", sd->protocol);
		return -1;
	}

	if ((inet_ntop(AF_INET, &(sd->r_addr), rhost, 16) == NULL) ||
		(inet_ntop(AF_INET, &(sd->l_addr), lhost, 16) == NULL)) {
		logmsg(LOG_ERR, 1, "logJSON: unable to convert IPv4 address into string.\n");
		return -1;
	}

	j_payload = json_object_new_object();
	if (convert_payload_to_json(&(sd->dl_payload), j_payload) < 0) {
		logmsg(LOG_ERR, 1, "logJSON: error while converting download payload information to JSON.\n");
		json_object_put(j_payload);
		return -1;
	}

	json_object_object_add(jd, "protocol", json_object_new_string(pent->p_name));
	json_object_object_add(jd, "remote_ip", json_object_new_string(rhost));
	json_object_object_add(jd, "remote_port", json_object_new_int(sd->r_port));
	json_object_object_add(jd, "local_ip", json_object_new_string(lhost));
	json_object_object_add(jd, "local_port", json_object_new_int(sd->l_port));
	json_object_object_add(jd, "type", json_object_new_string(sd->dl_type));
	json_object_object_add(jd, "username", json_object_new_string(sd->user));
	json_object_object_add(jd, "password", json_object_new_string(sd->pass));
	json_object_object_add(jd, "uri", json_object_new_string(sd->uri));
	json_object_object_add(jd, "filename", json_object_new_string(sd->filename));
	json_object_object_add(jd, "payload", j_payload);

	return 0;
}

int convert_connection_to_json(struct s_conn *sc, json_object *jc) {
	json_object *j_payload;
	struct protoent *pent;
	char rhost[16], lhost[16];

	if ((pent = getprotobynumber(sc->protocol)) == NULL) {
		logmsg(LOG_ERR, 1, "logJSON: unable to determine name for protocol %d.\n", sc->protocol);
		return -1;
	}

	if ((inet_ntop(AF_INET, &(sc->r_addr), rhost, 16) == NULL) ||
		(inet_ntop(AF_INET, &(sc->l_addr), lhost, 16) == NULL)) {
		logmsg(LOG_ERR, 1, "logJSON: unable to convert IPv4 address into string.\n");
		return -1;
	}

	j_payload = json_object_new_object();
	if (convert_payload_to_json(&(sc->payload), j_payload) < 0) {
		logmsg(LOG_ERR, 1, "logJSON: error while converting connection payload information to JSON.\n");
		json_object_put(j_payload);
		return -1;
	}

	json_object_object_add(jc, "protocol", json_object_new_string(pent->p_name));
	json_object_object_add(jc, "remote_ip", json_object_new_string(rhost));
	json_object_object_add(jc, "remote_port", json_object_new_int(sc->r_port));
	json_object_object_add(jc, "local_ip", json_object_new_string(lhost));
	json_object_object_add(jc, "local_port", json_object_new_int(sc->l_port));
	json_object_object_add(jc, "payload", j_payload);

	return 0;
}

int convert_attack_to_json(struct s_attack *sa, json_object *ja) {
	json_object *j_attack_c, *j_proxy_c, *j_downloads, *j_download;
	char stime[40], etime[40];
	int d;

	if ((strftime(stime, 40, "%FT%TZ", gmtime(&(sa->start_time))) == 0) ||
		(strftime(etime, 40, "%FT%TZ", gmtime(&(sa->end_time))) == 0)) {
		logmsg(LOG_ERR, 1, "logJSON: unable to convert attack timestamps.\n");
		return -1;
	}

	j_attack_c = json_object_new_object();
	if (convert_connection_to_json(&(sa->a_conn), j_attack_c) < 0) {
		logmsg(LOG_ERR, 1, "logJSON: error while converting attack connection information to JSON.\n");
		json_object_put(j_attack_c);
		return -1;
	}

	j_proxy_c = json_object_new_object();
	if (convert_connection_to_json(&(sa->p_conn), j_proxy_c) < 0) {
		logmsg(LOG_ERR, 1, "logJSON: error while converting proxy/mirror connection information to JSON.\n");
		json_object_put(j_proxy_c);
		return -1;
	}

	// XXX The following "download" section is patched in order to avoid using
	// a JSON array. The outer array has instead been converted to an object,
	// and an integer suffix has been appended to the inner object keys.

	// j_downloads = json_object_new_array();
	j_downloads = json_object_new_object();
	for (d = 0; d < sa->dl_count; ++d) {

		j_download = json_object_new_object();
		if (convert_download_to_json(&(sa->download[d]), j_download) < 0) {
			logmsg(LOG_ERR, 1, "logJSON: error while converting download[%d] information to JSON.\n", d);
			json_object_put(j_downloads);
			json_object_put(j_download);
			return -1;
		}

		// json_object_array_add(j_downloads, j_download);
		char key_d[256];
		json_object_object_foreach(j_download, key, value) {
			sprintf(key_d, "%s_%i", key, d);
			json_object_object_add(j_downloads, key_d, value);
		}
		json_object_put(j_download);

	}

	json_object_object_add(ja, "is_virtual", json_object_new_boolean(sa->virtual));
	json_object_object_add(ja, "@timestamp", json_object_new_string(stime));
	json_object_object_add(ja, "start_time", json_object_new_string(stime));
	json_object_object_add(ja, "end_time", json_object_new_string(etime));
	json_object_object_add(ja, "attack_connection", j_attack_c);
	json_object_object_add(ja, "proxy_connection", j_proxy_c);
	json_object_object_add(ja, "operation_mode", json_object_new_int(sa->op_mode));
	json_object_object_add(ja, "download_count", json_object_new_int(sa->dl_count));
	json_object_object_add(ja, "download_tries", json_object_new_int(sa->dl_tries));
	json_object_object_add(ja, "downloads", j_downloads);

	return 0;
}

int logjson(Attack *attack) {
	json_object *j_log;
	
	j_log = json_object_new_object();
	if (convert_attack_to_json(attack, j_log) < 0) {
		logmsg(LOG_ERR, 1, "logJSON: error while converting attack information to JSON.\n");
		json_object_put(j_log);
		return -1;
	}

	logmsg(LOG_DEBUG, 1, "logJSON: logging attacker information...\n");
	if (fprintf(f, "%s\n", json_object_to_json_string(j_log)) < 0) {
		logmsg(LOG_ERR, 1, "logJSON: could not write to log file. %s.\n", strerror(errno));
		json_object_put(j_log);
		return -1;
	}

	json_object_put(j_log);
	return 0;
}

conf_node *plugin_process_confopts(conf_node *tree, conf_node *node, void *opt_data) {
	char		*value = NULL;
	conf_node	*confopt = NULL;

	if ((confopt = check_keyword(tree, node->keyword)) == NULL) return(NULL);

	while (node->val) {
		if ((value = malloc(node->val->size+1)) == NULL) {
			perror("  ERROR: unable to allocate memory");
			exit(EXIT_FAILURE);
		}
		memset(value, 0, node->val->size+1);
		memcpy(value, node->val->data, node->val->size);

		node->val = node->val->next;

		if OPT_IS("logfile") {
			logfile = value;
		} else {
			fprintf(stderr, "  ERROR: invalid configuration option for plugin %s: %s\n", module_name, node->keyword);
			exit(EXIT_FAILURE);
		}
	}
	return(node);
}

void plugin_register_hooks(void) {
	logmsg(LOG_DEBUG, 1, "	  Plugin %s: registering hooks.\n", module_name);
	add_attack_func_to_list(PPRIO_PREPROC, module_name, "logjson", (void *) logjson);

	return;
}

void plugin_config(void) {
	register_plugin_confopts(module_name, config_keywords, sizeof(config_keywords)/sizeof(char *));
	if (process_conftree(config_tree, config_tree, plugin_process_confopts, NULL) == NULL) {
		fprintf(stderr, "  ERROR: unable to process configuration tree for plugin %s.\n", module_name);
		exit(EXIT_FAILURE);
	}
	return;
}

void plugin_init(void) {
	mode_t prevmode;

	// open log file
	logmsg(LOG_DEBUG, 1, "	  Plugin %s: opening log file %s.\n", module_name, logfile);

	prevmode = umask(S_IWGRP | S_IWOTH);
	if ((f = fopen(logfile, "a")) == NULL) {
		fprintf(stderr, "  ERROR: unable to open attacker log file. %s.\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	umask(prevmode);

	plugin_register_hooks();

	return;
}

void plugin_unload(void) {
	unhook(PPRIO_PREPROC, module_name, "logjson");

	// close log file
	fclose(f);

	return;
}
