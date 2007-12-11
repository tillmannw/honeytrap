/* htm_submitMWserv.c
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
 *   submit sampels to a central repository
 */

#define _GNU_SOURCE 1

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

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <curl.h>

#include <conftree.h>
#include <honeytrap.h>
#include <logging.h>
#include <plughook.h>
#include <readconf.h>
#include <signals.h>
#include <tcpip.h>
#include <util.h>

#include "htm_submitMWserv.h"


#define	TSS_ERROR	0
#define TSS_UNKNOWN	1
#define TSS_OK		2
#define TSS_HEARTBEAT	3
#define TSS_INCOMPLETE	4

#define ST_SUBMIT	1
#define ST_HASHTEST	2
#define ST_HEARTBEAT	3


const char module_name[]="submitMwserv";
const char module_version[]="0.1.0";

static const char *config_keywords[] = {
	"mwserv-url",
	"guid",
	"maintainer",
	"secret"
};

char	*mwserv_url;

const char	*guid;
const char	*maintainer;
const char	*secret;
u_char		timeout;


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

		if OPT_IS("mwserv-url") {
			mwserv_url = value;
		} else if OPT_IS("guid") {
			guid = value;
		} else if OPT_IS("maintainer") {
			maintainer = value;
		} else if OPT_IS("secret") {
			secret = value;
		} else if OPT_IS("timeout") {
			timeout = atoi(value);
			if (timeout < 1 || timeout > 60) {
				fprintf(stderr, "  Error - The value for %s in plugin %s must be between 1 and 60.\n", module_name, node->keyword);
				exit(EXIT_FAILURE);
			}
		} else {
			fprintf(stderr, "  Error - Invalid configuration option for plugin %s: %s\n", module_name, node->keyword);
			exit(EXIT_FAILURE);
		}
	}
	return(node);
}

int build_uri(char **uri, struct s_download download) {
	// build a generic malware URI of format 'type://user:pass@path/to/file:port/protocol'

	logmsg(LOG_DEBUG, 1, "SavePostgres - Building generic malware resource URI.\n");
	return(asprintf(uri, "%s://%s:%s@%s:%d/%s:%s",
		download.dl_type,
		download.user,
		download.pass,
		inet_ntoa(*(struct in_addr*)&download.r_addr),
		download.r_port,
		PROTO(download.protocol),
		download.filename));
}


size_t get_response(void *buffer, size_t s, size_t n, void *response) {
	// assemble server response
	
	if ((((bstr *)response)->data = realloc(((bstr *)response)->data, ((((bstr *)response)->len + n) * s))) == NULL) {
		logmsg(LOG_ERR, 1, "SubmitMWServ Error - Unable to allocate memory: %m.\n");
		return(0);
	}

	memcpy(((bstr *)response)->data + s * ((bstr *)response)->len, buffer, s*n);
	((bstr *)response)->len += s*n;
	return(s * n);
}


int response_code(const bstr *response) {
	if (response->len >= 9 && memcmp(response->data, "UNKNOWN", 7) == 0) return(TSS_UNKNOWN);
	if (response->len >= 4 && memcmp(response->data, "OK", 2) == 0) return(TSS_OK);
//	if (response->len >= 7 && memcmp(response->data, "ERROR: ", 7) == 0) return(TSS_ERROR);
//	if (response->len >= 11 && memcmp(response->data, "HEARTBEAT: ", 4) == 0) return(TSS_HEARTBEAT);
	return(TSS_ERROR);
}


int transfer_data(CURLM *mhandle, const bstr *response) {
	int		max_fd, rv, handles;
	fd_set		rfds, wfds, efds;
	struct timeval	select_timeout;
	CURLMcode	error;

	rv	= 1;
	while(rv) {
		FD_ZERO(&rfds);
		FD_ZERO(&wfds);
		FD_ZERO(&efds);
		
		max_fd = 0;
		if ((error = curl_multi_fdset(mhandle, &rfds, &wfds, &efds, &max_fd))) {
			logmsg(LOG_ERR, 1, "SubmitMWServ Error - Unable to get descriptor set: %s.\n", curl_multi_strerror(error));
			return(0);
		}
		FD_SET(sigpipe[0], &rfds);
		max_fd = MAX(max_fd, sigpipe[0]);

		select_timeout.tv_sec	= timeout;
		select_timeout.tv_usec	= 0;
		
		logmsg(LOG_DEBUG, 1, "SubmitMWServ - Submitting data to %s.\n", mwserv_url);

		switch (rv = select(max_fd+1, &rfds, &wfds, &efds, &select_timeout)) {
		case -1:
			if (errno != EINTR) {
				logmsg(LOG_ERR, 1, "SubmitMWServ Error - Select failed: %s.\n", strerror(errno));
				return(-1);
			}
			break;
		case 0:
			logmsg(LOG_WARN, 1, "SubmitMWServ Warning - Select timed out.\n");

			switch(response_code(response)) {
			case TSS_ERROR:
				return(TSS_ERROR);
			case TSS_UNKNOWN:
				return(TSS_UNKNOWN);
			case TSS_OK:
				return(TSS_OK);
			case TSS_INCOMPLETE:
			default:
				return(TSS_ERROR);
			}

			break;
		default:
			if (FD_ISSET(sigpipe[0], &rfds) && (check_sigpipe() == -1)) exit(EXIT_FAILURE);

			handles = 0;
			logmsg(LOG_DEBUG, 1, "SubmitMWServ - Data to process.\n");
			while(curl_multi_perform(mhandle, &handles) == CURLM_CALL_MULTI_PERFORM && handles);

			switch(response_code(response)) {
			case TSS_ERROR:
				return(TSS_ERROR);
			case TSS_UNKNOWN:
				return(TSS_UNKNOWN);
			case TSS_OK:
				return(TSS_OK);
			case TSS_INCOMPLETE:
			default:
				continue;
			}
			break;
		}
	}
	return(0);
}


struct curl_httppost *init_handle(CURLM **multihandle, CURL **curlhandle, const Attack *a, const int dlnum,
		const char* uri, const bstr *response, const u_char type) {

	int			handles;
	struct curl_httppost	*pinfo;
	struct curl_httppost	*pinfo_last;
	char 			*saddr_str, *daddr_str;

	pinfo = pinfo_last	= NULL;

	if (((daddr_str = strdup(inet_ntoa(*(struct in_addr *)&(a->download[dlnum].l_addr)))) == NULL) || 
	    ((saddr_str = strdup(inet_ntoa(*(struct in_addr *)&(a->download[dlnum].r_addr)))) == NULL)) {
		logmsg(LOG_ERR, 1, "SubmitMWServ Error - Unable to allocate memory: %m.\n");
		return(NULL);
	}

	logmsg(LOG_DEBUG, 1, "SubmitMWServ - Creating easy handle.\n");
	if (!(*curlhandle = curl_easy_init()) || !(*multihandle = curl_multi_init())) {
		logmsg(LOG_ERR, 1, "SubmitMWserv - Unable to create easy hanlde.\n");
		return(NULL);
	}

	
	logmsg(LOG_NOISY, 1, "SubmitMWServ - Constructing HTTP form for request type %d.\n", type);
	
	curl_formadd(&pinfo, &pinfo_last, CURLFORM_PTRNAME, "guid", CURLFORM_PTRCONTENTS, guid, CURLFORM_END);
	curl_formadd(&pinfo, &pinfo_last, CURLFORM_PTRNAME, "maintainer", CURLFORM_PTRCONTENTS, maintainer, CURLFORM_END);
	curl_formadd(&pinfo, &pinfo_last, CURLFORM_PTRNAME, "secret", CURLFORM_PTRCONTENTS, secret, CURLFORM_END); 

	curl_formadd(&pinfo, &pinfo_last, CURLFORM_PTRNAME, "uri",
		CURLFORM_PTRCONTENTS, uri, CURLFORM_CONTENTSLENGTH, strlen(uri), CURLFORM_END);
	curl_formadd(&pinfo, &pinfo_last, CURLFORM_PTRNAME, "sha512",
		CURLFORM_PTRCONTENTS, a->download[dlnum].dl_payload.sha512sum, CURLFORM_END);
	curl_formadd(&pinfo, &pinfo_last, CURLFORM_PTRNAME, "saddr",
		CURLFORM_COPYCONTENTS, saddr_str, CURLFORM_END);
	curl_formadd(&pinfo, &pinfo_last, CURLFORM_PTRNAME, "daddr",
		CURLFORM_COPYCONTENTS, daddr_str, CURLFORM_END);

	free(saddr_str);
	free(daddr_str);

	switch(type) {
	case ST_HASHTEST:
		break;

	case ST_SUBMIT:
		
		curl_formadd(&pinfo, &pinfo_last, CURLFORM_PTRNAME, "data",
			CURLFORM_PTRCONTENTS, a->download[dlnum].dl_payload.data,
			CURLFORM_CONTENTSLENGTH, a->download[dlnum].dl_payload.size, CURLFORM_END);

		// attack: cli:port->srv:port, mode
		break;
	
	default:
		logmsg(LOG_ERR, 1, "SubmitMWServ Error - Unknown message tyoe: %d.\n", type);
		return(NULL);
	}

	curl_easy_setopt(*curlhandle, CURLOPT_HTTPPOST, pinfo);
	curl_easy_setopt(*curlhandle, CURLOPT_FORBID_REUSE, 1);
	curl_easy_setopt(*curlhandle, CURLOPT_SSL_VERIFYHOST, 0);
	curl_easy_setopt(*curlhandle, CURLOPT_SSL_VERIFYPEER, 0);
	curl_easy_setopt(*curlhandle, CURLOPT_URL, mwserv_url);
	curl_easy_setopt(*curlhandle, CURLOPT_USERAGENT, "honeytrap " VERSION " (" MY_OS ", " MY_ARCH ", " MY_COMPILER ")");
	curl_easy_setopt(*curlhandle, CURLOPT_WRITEDATA, response);
	curl_easy_setopt(*curlhandle, CURLOPT_WRITEFUNCTION, get_response);

	logmsg(LOG_DEBUG, 1, "SubmitMWServ - Creating multi handle.\n");
	CURLMcode error;
	if ((error = curl_multi_add_handle(*multihandle, *curlhandle))) {
		logmsg(LOG_ERR, 1, "SubmitMWServ Error - Unable to create multi handle: %s\n", curl_multi_strerror(error));
		curl_easy_cleanup(*curlhandle);
		return(NULL);
	}

	handles	= 0;
	while(curl_multi_perform(*multihandle, &handles) == CURLM_CALL_MULTI_PERFORM && handles);

	return(pinfo);
}


int submit_mwserv(Attack *attack) {
	int			i;
	CURL			*curlhandle;
	CURLM			*multihandle;
	struct curl_httppost	*pinfo;
	char			*uri;
	bstr			response;

	/* no data - nothing todo */
	if (!attack->download) {
		logmsg(LOG_DEBUG, 1, "SubmitMWserv - No samples attached to attack record, nothing to submit.\n");
		return(0);
	}

	logmsg(LOG_DEBUG, 1, "SubmitMWserv - Submitting %d sample(s) to malware server.\n", attack->dl_count);

	/* save malware */
	for (i=0; i<attack->dl_count; i++) {
		if (build_uri(&uri, attack->download[i]) == -1) {
			logmsg(LOG_ERR, 1, "SubmitMWServ Error - Unable to create URI: %m.\n");
			return(0);
		}
		logmsg(LOG_DEBUG, 1, "SubmitMWServ - Sampel URI is '%s'\n", uri);


		// test hash
		logmsg(LOG_INFO, 1, "SubmitMWServ - Checking SHA512 hash at %s.\n", mwserv_url);
		memset(&response, 0, sizeof(bstr));
		
		if ((pinfo = init_handle(&multihandle, &curlhandle, attack, i, uri, &response, ST_HASHTEST)) == NULL) {
			free(response.data);
			return(0);
		}


		// check transfer status
		switch(transfer_data(multihandle, &response)) {
		case TSS_OK:
			logmsg(LOG_NOTICE, 1, "SubmitMWServ - Sample is already present, skipping submission.\n");
			return(1);
		case TSS_UNKNOWN:
			logmsg(LOG_NOTICE, 1, "SubmitMWServ - Sample is unknown, preparing submission.\n");
			break;
		case TSS_ERROR:
			logmsg(LOG_ERR, 1, "SubmitMWServ Error - Hash test failed.\n");
			return(0);
		default:
			logmsg(LOG_ERR, 1, "SubmitMWServ Error - Unknown server response.\n");
			return(0);
		}


		// prepare sample submission form
		free(response.data);
		if (multihandle) {
			curl_multi_remove_handle(multihandle, curlhandle);
			curl_multi_cleanup(multihandle);
			multihandle = NULL;
		}
		if (pinfo) curl_formfree(pinfo);
		if (curlhandle) curl_easy_cleanup(curlhandle);


		// submit sample
		logmsg(LOG_INFO, 1, "SubmitMWServ - Submitting sample to %s.\n", mwserv_url);
		memset(&response, 0, sizeof(bstr));

		if ((pinfo = init_handle(&multihandle, &curlhandle, attack, i, uri, &response, ST_SUBMIT)) == NULL) {
			free(uri);
			free(response.data);
			return(0);
		}

		if (transfer_data(multihandle, &response) == TSS_OK)
			logmsg(LOG_NOTICE, 1, "SubmitMWServ - Sample successfully submitted to %s.\n", mwserv_url);
		else
			logmsg(LOG_ERR, 1, "SubmitMWServ Error - Sample submission failed.\n");

		free(uri);
		free(response.data);

		if (multihandle) {
			curl_multi_remove_handle(multihandle, curlhandle);
			curl_multi_cleanup(multihandle);
			multihandle = NULL;
		}
		if (pinfo) curl_formfree(pinfo);
		if (curlhandle) curl_easy_cleanup(curlhandle);
	}

	return(1);
}
