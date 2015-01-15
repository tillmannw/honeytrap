/* htm_submitMWserv.c
 * Copyright (C) 2007-2015 Tillmann Werner <tillmann.werner@gmx.de>
 * Copyright (C) 2008 Georg Wicherski <gw@mwcollect.org>
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
 *   Submits malware samples to the mwcollect malware repository.
 *   For more info visit http://alliance.mwcollect.org.
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

#include <curl/curl.h>

#include <conftree.h>
#include <event.h>
#include <honeytrap.h>
#include <logging.h>
#include <plughook.h>
#include <readconf.h>
#include <sha512.h>
#include <signals.h>
#include <tcpip.h>
#include <util.h>

#include "htm_submitMWserv.h"


#define	TSS_ERROR	0
#define TSS_UNKNOWN	1
#define TSS_OK		2

#define ST_SUBMIT	1
#define ST_HASHTEST	2
#define ST_HEARTBEAT	3

#define HEARTBEAT_INTERVAL 180	// send a heartbeat every 180 seconds

const char module_name[]="submitMwserv";
const char module_version[]="1.0.1";

static const char *config_keywords[] = {
	"mwserv_url",
	"guid",
	"maintainer",
	"secret"
};

const char	*mwserv_url;
char * submit_url;
char * heartbeat_url;

const char	*guid;
const char	*maintainer;
const char	*secret;
u_int16_t	timeout;


void plugin_config(void) {
	register_plugin_confopts(module_name, config_keywords, sizeof(config_keywords)/sizeof(char *));
	if (process_conftree(config_tree, config_tree, plugin_process_confopts, NULL) == NULL) {
		fprintf(stderr, "  Error - Unable to process configuration tree for plugin %s.\n", module_name);
		exit(EXIT_FAILURE);
	}
	send_heartbeat();
	return;
}

void plugin_init(void) {
	plugin_register_hooks();
	return;
}

void plugin_unload(void) {
	unhook(PPRIO_SAVEDATA, module_name, "submit_mwserv");
	free(submit_url);
	return;
}

void plugin_register_hooks(void) {
	logmsg(LOG_DEBUG, 1, "    Plugin %s: Registering hooks.\n", module_name);
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

		if OPT_IS("mwserv_url") {
			mwserv_url = value;
			asprintf(&submit_url, "%shoneytrap/submit", mwserv_url);
			asprintf(&heartbeat_url, "%sheartbeat", mwserv_url);
		} else if OPT_IS("guid") {
			guid = value;
		} else if OPT_IS("maintainer") {
			maintainer = value;
		} else if OPT_IS("secret") {
			secret = value;
		} else if OPT_IS("timeout") {
			timeout = atoi(value);
			if (timeout < 1 || timeout > 360) {
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

	logmsg(LOG_DEBUG, 1, "SubmitMWserv - Building generic malware resource URI.\n");

	if (strlen(download.dl_type) == 3 && !strcmp(download.dl_type, "ftp"))
		return(asprintf(uri, "%s://%s:%s@%s:%d/%s:%s",
			download.dl_type,
			download.user,
			download.pass,
			inet_ntoa(*(struct in_addr*)&download.r_addr),
			download.r_port,
			PROTO(download.protocol),
			download.filename));

	if (strlen(download.dl_type) == 4 && !strcmp(download.dl_type, "tftp"))
		return(asprintf(uri, "%s://%s:%d/%s:%s",
			download.dl_type,
			inet_ntoa(*(struct in_addr*)&download.r_addr),
			download.r_port,
			PROTO(download.protocol),
			download.filename));

	return(-1);
}


size_t get_response(void *buffer, size_t s, size_t n, void *response) {
	// assemble server response
	
	if ((((bstr *)response)->data = realloc(((bstr *)response)->data, ((((bstr *)response)->len + n) * s))) == NULL) {
		logmsg(LOG_ERR, 1, "SubmitMWserv Error - Unable to allocate memory: %m.\n");
		return(0);
	}

	memcpy(((bstr *)response)->data + s * ((bstr *)response)->len, buffer, s*n);
	((bstr *)response)->len += s*n;
	return(s * n);
}


int response_code(const bstr *response) {
	if (response->len >= 7 && memcmp(response->data, "UNKNOWN", 7) == 0) return(TSS_UNKNOWN);
	if (response->len >= 2 && memcmp(response->data, "OK", 2) == 0) return(TSS_OK);	
	return(TSS_ERROR);
}


int check_response(const bstr *response) {
	switch(response_code(response)) {
	case TSS_OK:
		logmsg(LOG_NOISY, 1, "SubmitMWserv - Server returned transfer status OK.\n");
		return(TSS_OK);
	case TSS_UNKNOWN:
		logmsg(LOG_WARN, 1, "SubmitMWserv - Server returned status UNKNOWN.\n");
		return(TSS_UNKNOWN);
	default:
		{
			char buf[response->len + 1];
	
			memcpy(buf, response->data, response->len);
			buf[response->len] = 0;
			
			logmsg(LOG_ERR, 1, "SubmitMWserv - Server returned unexpected response \"%s\".\n", buf);
			return TSS_ERROR;
		}
	}
}

int transfer_data(CURLM *mhandle, const bstr *response) {
	int		max_fd, rv, handles;
	fd_set		rfds, wfds, efds;
	CURLMcode	error;

	rv	= 1;
	while(rv >= 0) {
		FD_ZERO(&rfds);
		FD_ZERO(&wfds);
		FD_ZERO(&efds);
		
		max_fd = 0;
		if ((error = curl_multi_fdset(mhandle, &rfds, &wfds, &efds, &max_fd))) {
			logmsg(LOG_ERR, 1, "SubmitMWserv Error - Unable to get descriptor set: %s.\n", curl_multi_strerror(error));
			return(0);
		}
		FD_SET(sigpipe[0], &rfds);
		max_fd = MAX(max_fd, sigpipe[0]);

		// logmsg(LOG_DEBUG, 1, "SubmitMWserv - Submitting data to %s.\n", mwserv_url);

		switch (rv = select(max_fd+1, &rfds, &wfds, &efds, NULL)) {
		case -1:
			if (errno != EINTR) {
				logmsg(LOG_ERR, 1, "SubmitMWserv Error - Select failed: %s.\n", strerror(errno));
				return(-1);
			}
			break;
		default:
		
			if (FD_ISSET(sigpipe[0], &rfds) && (check_sigpipe() == -1)) {
				fprintf(stderr, "SubmitMWserv Error - Select failed.\n");
				exit(EXIT_FAILURE);
			}

			handles = 0;
			//logmsg(LOG_DEBUG, 1, "SubmitMWserv - Data to process.\n");
			
			while(curl_multi_perform(mhandle, &handles) == CURLM_CALL_MULTI_PERFORM && handles);
			
			CURLMsg * message;
			int messagesRemaining;
			
			while((message = curl_multi_info_read(mhandle, &messagesRemaining))) {
				if(message->msg == CURLMSG_DONE) {
					if(message->data.result) {
						logmsg(LOG_ERR, 1, "SubmitMWserv Error - HTTP failure: %s\n", curl_easy_strerror(message->data.result));
						return TSS_ERROR;
					} else return check_response(response);
				}
			}
		}
	}
	return(0);
}


struct curl_httppost *init_handle(CURLM **multihandle, CURL **curlhandle,
		const Attack *attack, const struct s_download *download,
		const char* uri, const bstr *response, const u_char type) {

	int			handles, rv;
	struct curl_httppost	*pinfo;
	struct curl_httppost	*pinfo_last;
	char			saddr[16], daddr[16], sport[6], dport[6];


	if (type != ST_HASHTEST && type != ST_SUBMIT && type != ST_HEARTBEAT) return(NULL);
	if (!download && type != ST_HEARTBEAT) return(NULL);

	pinfo = pinfo_last = NULL;
	memset(saddr, 0, 16);
	memset(daddr, 0, 16);
	memset(sport, 0, 6);
	memset(dport, 0, 6);

	logmsg(LOG_DEBUG, 1, "SubmitMWserv - Creating easy handle.\n");
	if (!(*curlhandle = curl_easy_init()) || !(*multihandle = curl_multi_init())) {
		logmsg(LOG_ERR, 1, "SubmitMWserv - Unable to create easy hanlde.\n");
		return(NULL);
	}
	
		
	logmsg(LOG_DEBUG, 1, "SubmitMWserv - Constructing HTTP form for request type %d.\n", type);
	
	if (guid)
		curl_formadd(&pinfo, &pinfo_last, CURLFORM_PTRNAME, "guid", CURLFORM_PTRCONTENTS, guid, CURLFORM_END);
	if (maintainer)
		curl_formadd(&pinfo, &pinfo_last, CURLFORM_PTRNAME, "maintainer", CURLFORM_PTRCONTENTS, maintainer, CURLFORM_END);
	if (secret)
		curl_formadd(&pinfo, &pinfo_last, CURLFORM_PTRNAME, "secret", CURLFORM_PTRCONTENTS, secret, CURLFORM_END); 

	if(type != ST_HEARTBEAT) {	
		if (download->dl_payload.sha512sum)
			curl_formadd(&pinfo, &pinfo_last, CURLFORM_PTRNAME, "sha512", CURLFORM_PTRCONTENTS, download->dl_payload.sha512sum, CURLFORM_END); 
		if (attack->a_conn.r_addr) {
			rv = snprintf(saddr, 16, "%s", inet_ntoa(*(struct in_addr *)&attack->a_conn.r_addr));
			if (rv == -1 || rv > 16) return(NULL);
			curl_formadd(&pinfo, &pinfo_last, CURLFORM_PTRNAME, "saddr", CURLFORM_COPYCONTENTS, saddr, CURLFORM_END); 
		}
		if (attack->a_conn.l_addr) {
			rv = snprintf(daddr, 16, "%s", inet_ntoa(*(struct in_addr *)&attack->a_conn.l_addr));
			if (rv == -1 || rv > 16) return(NULL);
			curl_formadd(&pinfo, &pinfo_last, CURLFORM_PTRNAME, "daddr", CURLFORM_COPYCONTENTS, daddr, CURLFORM_END); 
		}
		if (attack->a_conn.r_port) {
			rv = snprintf(sport, 6, "%d", attack->a_conn.r_port);
			if (rv == -1 || rv > 16) return(NULL);
			curl_formadd(&pinfo, &pinfo_last, CURLFORM_PTRNAME, "sport", CURLFORM_COPYCONTENTS, sport, CURLFORM_END); 
		}
		if (attack->a_conn.l_port) {
			rv = snprintf(dport, 6, "%d", attack->a_conn.l_port);
			if (rv == -1 || rv > 16) return(NULL);
			curl_formadd(&pinfo, &pinfo_last, CURLFORM_PTRNAME, "dport", CURLFORM_COPYCONTENTS, dport, CURLFORM_END); 
		}
		if (uri) {
			curl_formadd(&pinfo, &pinfo_last, CURLFORM_PTRNAME, "url",
					CURLFORM_PTRCONTENTS, uri, CURLFORM_CONTENTSLENGTH, strlen(uri), CURLFORM_END);
		}

		if (type == ST_SUBMIT)
			curl_formadd(&pinfo, &pinfo_last, CURLFORM_PTRNAME, "data",
					CURLFORM_PTRCONTENTS, download->dl_payload.data,
					CURLFORM_CONTENTSLENGTH, download->dl_payload.size,
					CURLFORM_END);
	}
	#define SW_STRING "honeytrap " VERSION " (" MY_OS ", " MY_ARCH ", " MY_COMPILER ")"
	else {
		curl_formadd(&pinfo, &pinfo_last, CURLFORM_PTRNAME, "software",
			CURLFORM_PTRCONTENTS, SW_STRING, CURLFORM_CONTENTSLENGTH, sizeof(SW_STRING) - 1, CURLFORM_END);
	}

	// attack: cli:port->srv:port, mode

	curl_easy_setopt(*curlhandle, CURLOPT_HTTPPOST, pinfo);
	curl_easy_setopt(*curlhandle, CURLOPT_FORBID_REUSE, 1);
	curl_easy_setopt(*curlhandle, CURLOPT_SSL_VERIFYHOST, 0);
	curl_easy_setopt(*curlhandle, CURLOPT_SSL_VERIFYPEER, 0);
	curl_easy_setopt(*curlhandle, CURLOPT_URL, type == ST_HEARTBEAT ? heartbeat_url : submit_url);
	curl_easy_setopt(*curlhandle, CURLOPT_USERAGENT, SW_STRING);
	curl_easy_setopt(*curlhandle, CURLOPT_WRITEDATA, response);
	curl_easy_setopt(*curlhandle, CURLOPT_WRITEFUNCTION, get_response);
	curl_easy_setopt(*curlhandle, CURLOPT_TIMEOUT, timeout);
	#undef SW_STRING

	logmsg(LOG_DEBUG, 1, "SubmitMWserv - Creating multi handle.\n");
	CURLMcode error;
	if ((error = curl_multi_add_handle(*multihandle, *curlhandle))) {
		logmsg(LOG_ERR, 1, "SubmitMWserv Error - Unable to create multi handle: %s\n", curl_multi_strerror(error));
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
		if (!attack->download[i].dl_payload.sha512sum) continue;

		// test hash
		logmsg(LOG_INFO, 1, "SubmitMWserv - Checking SHA512 hash at %s.\n", mwserv_url);
		memset(&response, 0, sizeof(bstr));

		if (build_uri(&uri, attack->download[i]) == -1) {
			logmsg(LOG_ERR, 1, "SubmitMWserv Error - Unable to create URI: %m.\n");
			return(0);
		}
		
		if ((pinfo = init_handle(&multihandle, &curlhandle, attack,
				&attack->download[i], uri, &response, ST_HASHTEST)) == NULL) {
			free(response.data);
			return(0);
		}

		switch (transfer_data(multihandle, &response))
		{
		case TSS_OK:
			logmsg(LOG_NOTICE, 1, "SubmitMWserv - Sample is already present at %s, skipping submission.\n", mwserv_url);
			free(response.data);
			
			continue;
		
		case TSS_ERROR:
			logmsg(LOG_ERR, 1, "SubmitMWserv Error - Hash test failed.\n");
			free(response.data);
			
			continue;
		}

		free(response.data);


		// submit sample
		logmsg(LOG_INFO, 1, "SubmitMWserv - Submitting sample to %s.\n", mwserv_url);

		memset(&response, 0, sizeof(bstr));
		
		if ((pinfo = init_handle(&multihandle, &curlhandle, attack,
				&attack->download[i], uri, &response, ST_SUBMIT)) == NULL) {
			free(uri);
			free(response.data);
			return(0);
		}

		if (transfer_data(multihandle, &response) == TSS_OK)
			logmsg(LOG_NOTICE, 1, "SubmitMWserv - Sample successfully submitted to %s.\n", mwserv_url);
		else
			logmsg(LOG_ERR, 1, "SubmitMWserv Error - Sample submission failed.\n");

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


int send_heartbeat(void) {
	CURL			*curlhandle;
	CURLM			*multihandle;
	struct curl_httppost	*pinfo;
	bstr			response = { 0 };
	time_t			t = time(0);

	if (!running) {
		// honeytrap is still busy setting up itself, try again in one second
		event_enqueue(t+1, send_heartbeat);
		return 1;
	}

	logmsg(LOG_DEBUG, 1, "SubmitMWserv - Forking child process.\n");

	switch(fork()) {
	case -1:
		logmsg(LOG_ERR, 1, "SubmitMWserv - Failed to fork for heartbeat: %s.\n", strerror(errno));
		return 0;
	case 0:
		// child sends heartbeat
		if ((pinfo = init_handle(&multihandle, &curlhandle, 0,
			0, 0, &response, ST_HEARTBEAT)) == NULL) {
			logmsg(LOG_ERR, 1, "SubmitMWserv - Could not initialize CURL handle!\n");
			return 0;
		}
	
		logmsg(LOG_DEBUG, 1, "SubmitMWserv - Sending heartbeat.\n");

		switch (transfer_data(multihandle, &response)) {
		case TSS_OK:
			logmsg(LOG_DEBUG, 1, "SubmitMWserv - Successfully sent heartbeat to %s.\n", heartbeat_url);
			break;
		
		case TSS_ERROR:
			logmsg(LOG_ERR, 1, "SubmitMWserv Error - Server %s reported error when sending heartbeat!\n", heartbeat_url);
			break;	
		}
		_exit(0);
	default:
		// enqueue next heartbeat event
		event_enqueue(t + HEARTBEAT_INTERVAL, send_heartbeat);
		break;
	}

	return 1;

}

