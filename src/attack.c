/* dynsrv.c
 * Copyright (C) 2005-2006 Tillmann Werner <tillmann.werner@gmx.de>
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
		a->a_conn.payload.data = (char *) malloc(a_size);
		memcpy(a->a_conn.payload.data, a_data, a_size);
	}

	memcpy(a->a_conn.payload.chksum, (char*)mem_md5sum(a->a_conn.payload.data, a->a_conn.payload.size), 33);
	/* mirror string */
	a->p_conn.payload.size = p_size;
	if (p_size) {
		a->p_conn.payload.data = (char *) malloc(p_size);
		memcpy(a->p_conn.payload.data, p_data, p_size);
	}
	memcpy((char *) &(a->p_conn.payload.chksum),
		(char *) mem_md5sum(a->p_conn.payload.data, a->p_conn.payload.size), 32);


	if (!a_size) {
		addr = (struct in_addr *) &(a->a_conn.r_addr);
		logmsg(LOG_NOTICE, 1, " * %u\t  No bytes received from %s:%u.\n",
		(uint16_t) a->a_conn.l_port, inet_ntoa(*addr), a->a_conn.r_port);
	} else {
		addr = (struct in_addr *) &(a->a_conn.r_addr);
		logmsg(LOG_NOTICE, 1, " * %u\t  %d bytes attack string from %s:%u.\n",
			(uint16_t) a->a_conn.l_port, a_size, inet_ntoa(*addr), a->a_conn.r_port);
	}

	/* call plugins */
	/* do calls even if no data received, i.e. to update connection statistics */
	plughook_process_attack(*a);

	return(1);
}
