/* attack.c
 * Copyright (C) 2005-2007 Tillmann Werner <tillmann.werner@gmx.de>
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

Attack *new_attack(struct in_addr l_addr, struct in_addr r_addr, uint16_t l_port, uint16_t r_port, uint16_t proto) {
	Attack *a;

	/* mem for attack record */
	if ((a = (Attack *) calloc(1, sizeof(Attack))) == NULL) return(NULL);

	/* store attack connection data in attack record */
	memcpy(&(a->a_conn.l_addr), &l_addr, sizeof(uint32_t));
	memcpy(&(a->a_conn.r_addr), &r_addr, sizeof(uint32_t));
	a->a_conn.l_port	= l_port;
	a->a_conn.r_port	= r_port;
	a->a_conn.protocol	= proto;
	a->dl_count		= 0;
	a->download		= NULL;
	if (time(&(a->start_time)) == ((time_t)-1)) 
		logmsg(LOG_WARN, 1, "Warning - Could not set attack start time: %s.\n", strerror(errno));

	return(a);
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
		logmsg(LOG_WARN, 1, "Warning - Could not set attack end time: %s.\n", strerror(errno));

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
	memcpy((char *) &(a->p_conn.payload.md5sum),
		(char *) mem_md5sum(a->p_conn.payload.data, a->p_conn.payload.size), 32);


	if (!a_size) {
		addr = (struct in_addr *) &(a->a_conn.r_addr);
		logmsg(LOG_NOTICE, 1, " * %u/%s\t  No bytes received from %s:%u.\n",
			(uint16_t) a->a_conn.l_port, PROTO(a->a_conn.protocol),
			inet_ntoa(*addr), a->a_conn.r_port);
	} else {
		addr = (struct in_addr *) &(a->a_conn.r_addr);
		logmsg(LOG_NOTICE, 1, " * %u/%s\t  %d bytes attack string from %s:%u.\n",
			(uint16_t) a->a_conn.l_port, PROTO(a->a_conn.protocol), a_size,
			inet_ntoa(*addr), a->a_conn.r_port);
	}

	/* call plugins */
	/* do calls even if no data received, i.e. to update connection statistics */
	logmsg(LOG_DEBUG, 1, "Calling plugins for hook 'process_attack'.\n");
	plughook_process_attack(funclist_attack_preproc, a);
	plughook_process_attack(funclist_attack_analyze, a);
	plughook_process_attack(funclist_attack_savedata, a);
	plughook_process_attack(funclist_attack_postproc, a);

	logmsg(LOG_DEBUG, 1, "Attack data processed.\n");
	return(1);
}

/* add a downloaded file to the attack instance */
int add_download(const char *dl_type, u_int16_t proto, const uint32_t r_addr, const uint16_t r_port, const char *user, const char *pass, const char *filename, const u_char *data, const u_int32_t size, Attack *a) {
	if ((data == NULL) || (!size))  return(0);

	if (a == NULL) {
		logmsg(LOG_ERR, 1, "Error - Could not add download: No attack record given.\n");
		return(-1);
	}

	if ((a->download = realloc(a->download, sizeof(struct s_download) * (a->dl_count + 1))) == NULL) {
		logmsg(LOG_ERR, 1, "Error - Unable to allocate memory: %s.\n", strerror(errno));
		return(-1);
	}

	if ((dl_type && ((a->download[a->dl_count].dl_type = strdup(dl_type)) == NULL)) ||
	    (filename && ((a->download[a->dl_count].filename = strdup(filename)) == NULL)) ||
	    (user && ((a->download[a->dl_count].user = strdup(user)) == NULL)) ||
	    (pass && ((a->download[a->dl_count].pass = strdup(pass)) == NULL)) ||
	    ((a->download[a->dl_count].dl_payload.data = (u_char *) malloc(size)) == NULL)) { 
		logmsg(LOG_ERR, 1, "Error - Unable to allocate memory: %s.\n", strerror(errno));
		free(a->download[a->dl_count].dl_type);
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
	a->dl_count++;

	logmsg(LOG_DEBUG, 1, "%d. malware download added to attack record.\n", a->dl_count);

	return(0);
}
