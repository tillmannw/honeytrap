/* attack.c
 * Copyright (C) 2005-2008 Tillmann Werner <tillmann.werner@gmx.de>
 *
 * This file is free software; as a special exception the author gives
 * unlimited permission to copy and/or distribute it, with or without
 * modifications, as long as this notice is preserved.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
 * implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */

#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <netdb.h>
#include <string.h>

#include "honeytrap.h"
#include "logging.h"
#include "dynsrv.h"
#include "response.h"
#include "md5.h"
#include "sha512.h"
#include "proxy.h"
#include "plughook.h"
#include "ipqmon.h"


Attack *new_virtattack(struct in_addr r_addr, struct in_addr l_addr, uint16_t r_port, uint16_t l_port, uint16_t proto) {
	Attack *a;

	if ((a = new_attack(r_addr, l_addr, r_port, l_port, proto)) == NULL) return NULL;

	a->virtual = 1;

	return(a);
}


Attack *new_attack(struct in_addr r_addr, struct in_addr l_addr, uint16_t r_port, uint16_t l_port, uint16_t proto) {
	Attack *a;

	/* mem for attack record */
	if ((a = (Attack *) calloc(1, sizeof(Attack))) == NULL) return NULL;

	/* store attack connection data in attack record */
	memcpy(&(a->a_conn.l_addr), &l_addr, sizeof(uint32_t));
	memcpy(&(a->a_conn.r_addr), &r_addr, sizeof(uint32_t));
	a->a_conn.l_port	= l_port;
	a->a_conn.r_port	= r_port;
	a->a_conn.protocol	= proto;
	a->dl_count		= 0;
	a->dl_tries		= 0;
	a->download		= NULL;
	if (time(&(a->start_time)) == ((time_t)-1)) 
		logmsg(LOG_WARN, 1, "Warning - Could not set attack start time: %m.\n");

	return(a);
}


void del_attack(Attack *a) {
	int i;

	if (!a) return;

	for (i=0; i<a->dl_count; ++i) {
		if (a->download[i].dl_type) free(a->download[i].dl_type);
		if (a->download[i].user) free(a->download[i].user);
		if (a->download[i].pass) free(a->download[i].pass);
		if (a->download[i].filename) free(a->download[i].filename);
		if (a->download[i].uri) free(a->download[i].uri);
		if (a->download[i].dl_payload.data) free(a->download[i].dl_payload.data);
	}

	if (a->a_conn.payload.data) free(a->a_conn.payload.data);
	if (a->p_conn.payload.data) free(a->p_conn.payload.data);

	free(a);

	return;
}


/* process attack - call plugins registered for hook 'process_attack' */
int process_data(u_char *a_data, uint32_t a_size, u_char *p_data, uint32_t p_size, uint16_t port, Attack *a) {
	struct in_addr *addr = NULL;

	if (a == NULL) {
		logmsg(LOG_ERR, 1, "Error - Could not process data: No attack record given.\n");
		return(-1);
	}

	/* save end time and payload data in attack record */
	if (time(&(a->end_time)) == ((time_t)-1)) 
		logmsg(LOG_WARN, 1, "Warning - Could not set attack end time: %m.\n");

	/* attack string */
	a->a_conn.payload.size = a_size;
	if (a_size) {
		a->a_conn.payload.data = (u_char *) malloc(a_size);
		memcpy(a->a_conn.payload.data, a_data, a_size);
	}

	memcpy(a->a_conn.payload.sha512sum, mem_sha512sum(a->a_conn.payload.data, a->a_conn.payload.size), 129);
	memcpy(a->a_conn.payload.md5sum, mem_md5sum(a->a_conn.payload.data, a->a_conn.payload.size), 33);

	/* mirror string */
	a->p_conn.payload.size = p_size;
	if (p_size) {
		a->p_conn.payload.data = (u_char *) malloc(p_size);
		memcpy(a->p_conn.payload.data, p_data, p_size);
	}
	memcpy((char *) &(a->p_conn.payload.sha512sum),
		(char *) mem_sha512sum(a->p_conn.payload.data, a->p_conn.payload.size), 129);
	memcpy((char *) &(a->p_conn.payload.md5sum),
		(char *) mem_md5sum(a->p_conn.payload.data, a->p_conn.payload.size), 32);


	if (!a_size) {
		addr = (struct in_addr *) &(a->a_conn.r_addr);
		logmsg(LOG_NOTICE, 1, " * %5u/%s  No bytes received from %s:%u.\n",
			(uint16_t) a->a_conn.l_port, PROTO(a->a_conn.protocol),
			inet_ntoa(*addr), a->a_conn.r_port);
	} else {
		addr = (struct in_addr *) &(a->a_conn.r_addr);
		logmsg(LOG_NOTICE, 1, " * %5u/%s  %d bytes attack string from %s:%u.\n",
			(uint16_t) a->a_conn.l_port, PROTO(a->a_conn.protocol), a_size,
			inet_ntoa(*addr), a->a_conn.r_port);
	}

	/* call plugins */
	/* do calls even if no data received, i.e. to update connection statistics */
	logmsg(LOG_DEBUG, 1, "Calling preprocessor plugins for hook 'process_attack'.\n");
	plughook_process_attack(funclist_attack_preproc, a);
	logmsg(LOG_DEBUG, 1, "Calling analyzer plugins for hook 'process_attack'.\n");
	plughook_process_attack(funclist_attack_analyze, a);
	logmsg(LOG_DEBUG, 1, "Calling savedata plugins for hook 'process_attack'.\n");
	plughook_process_attack(funclist_attack_savedata, a);
	logmsg(LOG_DEBUG, 1, "Calling postprocessor plugins for hook 'process_attack'.\n");
	plughook_process_attack(funclist_attack_postproc, a);

	logmsg(LOG_DEBUG, 1, "Attack data processed.\n");
	return(1);
}

/* add a downloaded file to the attack instance */
int add_download(const char *dl_type, u_int16_t proto, const uint32_t r_addr, const uint16_t r_port, const char *user, const char *pass, const char *filename, const char *uri, const u_char *data, const u_int32_t size, Attack *a) {
	if ((data == NULL) || (!size))  return(0);

	if (a == NULL) {
		logmsg(LOG_ERR, 1, "Error - Could not add download: No attack record given.\n");
		return(-1);
	}

	if ((a->download = realloc(a->download, sizeof(struct s_download) * (a->dl_count + 1))) == NULL) {
		logmsg(LOG_ERR, 1, "Error - Unable to allocate memory: %m.\n");
		return(-1);
	}

	memset(&a->download[a->dl_count], 0, sizeof(struct s_download));

	if ((dl_type && ((a->download[a->dl_count].dl_type = strdup(dl_type)) == NULL)) ||
	    (filename && ((a->download[a->dl_count].filename = strdup(filename)) == NULL)) ||
	    (user && ((a->download[a->dl_count].user = strdup(user)) == NULL)) ||
	    (pass && ((a->download[a->dl_count].pass = strdup(pass)) == NULL)) ||
	    (uri && ((a->download[a->dl_count].uri = strdup(uri)) == NULL)) ||
	    ((a->download[a->dl_count].dl_payload.data = (u_char *) malloc(size)) == NULL)) { 
		logmsg(LOG_ERR, 1, "Error - Unable to allocate memory: %m.\n");
		free(a->download[a->dl_count].dl_type);
		free(a->download[a->dl_count].uri);
		free(a->download[a->dl_count].user);
		free(a->download[a->dl_count].pass);
		free(a->download[a->dl_count].filename);
		free(a->download[a->dl_count].dl_payload.data);
		return(-1);
	}
	memcpy(a->download[a->dl_count].dl_payload.data, data, size);
	memcpy(a->download[a->dl_count].dl_payload.md5sum, mem_md5sum(a->download->dl_payload.data, size), 33);
	memcpy(a->download[a->dl_count].dl_payload.sha512sum, mem_sha512sum(a->download->dl_payload.data, size), 129);

	a->download[a->dl_count].protocol		= proto;
	a->download[a->dl_count].dl_payload.size	= size;
	a->download[a->dl_count].r_addr			= r_addr;
	a->download[a->dl_count].r_port			= r_port;
	a->download[a->dl_count].l_addr			= a->a_conn.l_addr;
	a->download[a->dl_count].l_port			= a->a_conn.l_port;
	a->dl_count++;

	logmsg(LOG_DEBUG, 1, "%d. malware download added to attack record.\n", a->dl_count);

	return(0);
}


int reassign_downloads(Attack *dst, Attack *src) {
	if (!dst || !src) {
		logmsg(LOG_ERR, 1, "Error - Could not reassign downloads: Attack record(s) missing.\n");
		return -1;
	}

	// reassign all downloads from src to dst
	if ((dst->download = realloc(dst->download, sizeof(struct s_download) * (dst->dl_count + src->dl_count))) == NULL) {
		logmsg(LOG_ERR, 1, "Error - Unable to allocate memory: %m.\n");
		return -1;
	}
	memcpy(&dst->download[dst->dl_count],
		src->download,
		sizeof(struct s_download) * src->dl_count);
	dst->dl_count += src->dl_count;

	free(src->download);
	src->download = NULL;
	src->dl_count = 0;

	return 0;
}
