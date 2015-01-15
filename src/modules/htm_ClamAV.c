/* htm_ClamAV.c
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
 *   This honeytrap module scans samples in an attack record
 *   for viruses using the signature-based libclamav.
 */

#define _GNU_SOURCE

#include <clamav.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h> 
#include <sys/stat.h> 
#include <unistd.h>

#include <honeytrap.h>
#include <logging.h>
#include <readconf.h>
#include <conftree.h>
#include <util.h>
#include <plughook.h>

#include "htm_ClamAV.h"


#ifdef CL_INIT_DEFAULT
#define NEW_CLAM_API 1	// CL_INIT_DEFAULT is only defined in libclamav >= 0.95
#endif


const char module_name[]="ClamAV";
const char module_version[]="1.0.1";

static const char *config_keywords[] = {
	"clamdb_path",
	"temp_dir"
};

const char *clamdb_path;
const char *temp_dir;

struct cl_engine *engine;

#ifndef NEW_CLAM_API
struct cl_limits limits;
#endif

void plugin_config(void) {
	register_plugin_confopts(module_name, config_keywords, sizeof(config_keywords)/sizeof(char *));
	if (process_conftree(config_tree, config_tree, plugin_process_confopts, NULL) == NULL) {
		fprintf(stderr, "  Error - Unable to process configuration tree for plugin %s.\n", module_name);
		exit(EXIT_FAILURE);
	}
	return;
}

void plugin_init(void) {
	load_clamdb();
	plugin_register_hooks();
	return;
}

void plugin_unload(void) {
	/* free memory */
#ifdef NEW_CLAM_API
	cl_engine_free(engine);
#else
	cl_free(engine);
#endif
	unhook(PPRIO_POSTPROC, module_name, "clamscan");
	return;
}

void plugin_register_hooks(void) {
	logmsg(LOG_DEBUG, 1, "    Plugin %s: Registering hooks.\n", module_name);
	add_attack_func_to_list(PPRIO_POSTPROC, module_name, "clamscan", (void *) clamscan);

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

		if OPT_IS("clamdb_path") {
			clamdb_path = value;
		} else if OPT_IS("temp_dir") {
			temp_dir = value;
		} else {
			fprintf(stderr, "  Error - Invalid configuration option for plugin %s: %s\n", module_name, node->keyword);
			exit(EXIT_FAILURE);
		}
	}
	return(node);
}

void load_clamdb(void) {
	int		ret;
	u_int32_t	sigs;

	ret	= 0;
	sigs	= 0;
	engine	= NULL;

	/* load databases */
	DEBUG_FPRINTF(stdout, "    ClamAV - Loading signature database, be patient.\n");
#ifdef NEW_CLAM_API
	if (cl_init(CL_INIT_DEFAULT) != CL_SUCCESS) {
		fprintf(stderr, "  ClamAV error - Unable to initialize scanning engine: %s.\n", cl_strerror(ret));
		exit(EXIT_FAILURE);
	}

	if ((engine = cl_engine_new()) == NULL) {
		fprintf(stderr, "  ClamAV error - Unable to create new scanning engine: %s.\n", cl_strerror(ret));
		exit(EXIT_FAILURE);
	}

	if ((ret = cl_load(clamdb_path ? clamdb_path : cl_retdbdir(), engine, &sigs, CL_DB_STDOPT)) != CL_SUCCESS) {
#else
	if ((ret = cl_load(clamdb_path ? clamdb_path : cl_retdbdir(), &engine, &sigs, CL_DB_STDOPT)) > 0) {
#endif
		fprintf(stderr, "  ClamAV error - Unable to load databases: %s.\n", cl_strerror(ret));
		exit(EXIT_FAILURE);
	}
	DEBUG_FPRINTF(stdout, "    ClamAV - Loaded %u signatures.\n", sigs);

	/* build engine */
#ifdef NEW_CLAM_API
	if ((ret = cl_engine_compile(engine)) != CL_SUCCESS) {
#else
	if (ret = cl_build(engine)) > 0) {
#endif
		fprintf(stderr, "    ClamAV error - Unable to initialize database: %s\n", cl_strerror(ret));;
#ifdef NEW_CLAM_API
		cl_engine_free(engine);
#else
		cl_free(engine);
#endif
		exit(EXIT_FAILURE);
	}
	DEBUG_FPRINTF(stdout, "    ClamAV - Signature database initialized.\n");

	/* set up archive limits */
#ifdef NEW_CLAM_API
	cl_engine_set_num(engine, CL_ENGINE_MAX_FILES, 1000);
	cl_engine_set_num(engine, CL_ENGINE_MAX_FILESIZE, 10 * 1048576);
	cl_engine_set_num(engine, CL_ENGINE_MAX_RECURSION, 5);
#else
	memset(&limits, 0, sizeof(struct cl_limits));
	limits.maxfiles		= 1000;		/* max files */
	limits.maxfilesize	= 10 * 1048576;	/* maximum size of archived/compressed file */
	limits.maxreclevel	= 5;		/* maximum recursion level for archives */
#endif

	return;
}

int clamscan(Attack *attack) {
	int			num_scanned, ret, tmpfd;
	unsigned long int	size;
	struct s_download	*sample;
	char			*tmpfile;
	const char		*virusname;

	num_scanned	= 0;
	ret		= 0;
	size		= 0;
	sample		= NULL;
	virusname	= NULL;

	/* no data - nothing todo */
	if ((!attack->dl_count) || (attack->download == NULL)) {
		logmsg(LOG_DEBUG, 1, "ClamAV - No samples found, nothing to scan.\n");
		return(0);
	}

	logmsg(LOG_DEBUG, 1, "ClamAV - Scanning %u samples.\n", attack->dl_count);

	sample = attack->download;
	while (num_scanned < attack->dl_count) {
		/* scan sample */
		logmsg(LOG_NOISY, 1, "ClamAV - Scanning sample %u.\n", num_scanned+1);

		/* libclamav can only scan files, so dump data to a secure temp file */
		if (asprintf(&tmpfile, "%s/honeytrap-clamav-XXXXXX", temp_dir) == -1) {
			logmsg(LOG_ERR, 1, "ClamAV error - Unable to create temporary file: %m.\n");
			return(-1);
		}
		if ((tmpfd = mkstemp(tmpfile)) < 0) {
			logmsg(LOG_ERR, 1, "ClamAV error - Unable to create temporary file: %s.\n", strerror(errno));
			return(-1);
		}

		/* dump sample to temp file */
		if (write(tmpfd, sample[num_scanned].dl_payload.data,  sample[num_scanned].dl_payload.size) == -1) {
			logmsg(LOG_ERR, 1, "ClamAV error - Unable to dump sample to file: %s.\n", strerror(errno));
			close(tmpfd);
			return(-1);
		}

		/* scan temp file */
#ifdef NEW_CLAM_API
		switch (ret = cl_scandesc(tmpfd, &virusname, &size, engine, CL_SCAN_STDOPT)) {
#else
		switch (ret = cl_scandesc(tmpfd, &virusname, &size, engine, &limits, CL_SCAN_STDOPT)) {
#endif
		case CL_CLEAN:
			logmsg(LOG_NOISY, 1, "ClamAV - Sample %u considered to be clean.\n", num_scanned+1);
			break;
		case CL_VIRUS:
			logmsg(LOG_INFO, 1, "ClamAV - Sample %u is infected with '%s'.\n", num_scanned+1, virusname);
			break;
		default:
			/* error during scan process */
			logmsg(LOG_ERR, 1, "ClamAV error - Unable to scan sample %u: %s.\n", num_scanned+1, cl_strerror(ret));
			break;
		}

		close(tmpfd);
		unlink(tmpfile);
		num_scanned++;
	}

	return(num_scanned);
}
