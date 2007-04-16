/* htm_aSavePostgres.c
 * Copyright (C) 2007 Tillmann Werner <tillmann.werner@gmx.de>,
 *                    Christoph Fuchs <christoph.fuchs@gmx.de>
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
 *   This honeytrap module submits a recorded attack to a PostgreSQL database.
 *   
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <postgresql/libpq-fe.h>

#include <logging.h>
#include <honeytrap.h>
#include <attack.h>
#include <ip.h>
#include <plughook.h>
#include <md5.h>

#include "htm_aSavePostgres.h"

void plugin_init(void) {
	/* TODO: register sensor in db, if not existent */
	plugin_register_hooks();
	return;
}


void plugin_unload(void) {
	unhook(PPRIO_SAVEDATA, module_name, "db_submit");
	return;
}


void plugin_register_hooks(void) {
	DEBUG_FPRINTF(stdout, "    Plugin %s: Registering hooks.\n", module_name);
	add_attack_func_to_list(PPRIO_SAVEDATA, module_name, "db_submit", (void *) db_submit);

	return;
}


int db_connect(void) {
	/* connect to database */
	if (PQstatus(db_connection = PQconnectdb(db_info)) != CONNECTION_OK) {
		logmsg(LOG_ERR, 1, "Error - Could not connect to database: %s.\n", PQerrorMessage(db_connection));
		PQfinish(db_connection);
		return(-1);
	}
	logmsg(LOG_NOISY, 1, "Attack database (Postgres) - Connection established.\n");
	if (PQsetClientEncoding(db_connection, "UTF8") != 0) {
		logmsg(LOG_ERR, 1, "Error - Could not set database character encoding to UTF8: %s.\n", PQerrorMessage(db_connection));
		PQfinish(db_connection);
		return(-1);
	}
	return(0);
}


void db_disconnect(void) {
	/* disconnect from database */
	PQfinish(db_connection);
	logmsg(LOG_NOISY, 1, "Attack database (Postgres) - Connection closed.\n");
	return;
}


char *build_url(struct s_download *download) {
	char		*url;		// generic malware URL format 'type://user:pass@path/to/file:port/protocol'

	if ((url = malloc(MAX_URL_SIZE + 1)) == NULL) {
		logmsg(LOG_ERR, 1, "Error - Unable to allocate memory: %s.\n", strerror(errno));
		return(NULL);
	}
	memset(url, 0, MAX_URL_SIZE+1);

	logmsg(LOG_DEBUG, 1, "Building generic malware resource URL.\n");

	/* should check for supported protocol types */
	if (!strlen(download->dl_type)) {
		logmsg(LOG_WARN, 1, "Database warning - Could not build URL: Unknown protocol type.\n");
		return(NULL);
	}
	logmsg(LOG_DEBUG, 1, "(Build URL): Typ: %s.\n",download->dl_type);
	snprintf(url + strlen(url), strlen(download->dl_type) + 3, "%s://", download->dl_type);

	if(strlen(download->user)) {
		logmsg(LOG_NOISY,1,"(Build URL): User: %s Pass: %s.\n", download->user, download->pass);
		snprintf(url + strlen(url), strlen(download->user) + strlen(download->pass) + 2, "%s:%s@", download->user, download->pass);
	}

	logmsg(LOG_NOISY, 1, "(Build URL): URL: %s.\n", inet_ntoa(*(struct in_addr*)&download->r_addr));
	strncat(url, inet_ntoa(*(struct in_addr*)&download->r_addr), strlen(inet_ntoa(*(struct in_addr*)&download->r_addr)));

	if (download->r_port) {
		logmsg(LOG_NOISY, 1, "(Build URL): Port: %d.\n", download->r_port);
		snprintf(url + strlen(url), 6, ":%d/", download->r_port);
		strcat(url + strlen(url), PROTO(download->protocol));
	}

	if (download->filename) {
		logmsg(LOG_NOISY, 1, "(Build URL): Filename: %s.\n", download->filename);
		snprintf(url + strlen(url), strlen(download->filename) + 1, "/%s", download->filename);
	}

	return(url);
}


int db_submit(Attack *attack) {
	PGresult	*res;
	char		*query, *starttime, *endtime, *url, *l_ip, *r_ip;
	u_char		*esc_bytea;
	int		mw_inst = -1;
	size_t		length;

	/* we only need to connect if we have data */
	if ((!attack->a_conn.payload.size) && (!attack->dl_count)) return(0); 

	logmsg(LOG_DEBUG, 1, "Attack database (Postgres) - Connecting to database.\n");
	if (db_connect() != 0) return(-1);

	/* Start a transaction block */
	if (PQresultStatus(res = PQexec(db_connection, "BEGIN")) != PGRES_COMMAND_OK) {
		logmsg(LOG_ERR, 1, "Database error - BEGIN command failed: %s.\n", PQerrorMessage(db_connection));
		PQclear(res);
		db_disconnect();
		return(-1);
	}
	PQclear(res);


	/* upload malware */
	if (attack->dl_count) {
		if ((query = malloc(MAX_SQL_BUFFER + 1)) == NULL) {
			logmsg(LOG_ERR, 1, "Error - Unable to allocate memory: %s.\n", strerror(errno));
			return(-1);
		}
		memset(query, 0, MAX_SQL_BUFFER + 1);

		/* escape byte data to prevent sql injection */
		if ((esc_bytea = PQescapeByteaConn(db_connection, attack->download->dl_payload.data, attack->download->dl_payload.size, &length)) == NULL) {
			logmsg(LOG_ERR, 1, "Database error - Could not escape attack string: %s.\n", PQerrorMessage(db_connection));
			PQclear(res);
			db_disconnect();
			free(query);
			return(-1);
		}

		mem_md5sum(attack->download->dl_payload.data,attack->download->dl_payload.size);

		if ((url = build_url(attack->download)) == NULL) {
			logmsg(LOG_WARN, 1, "Warning - Unable to build generic malware URL.\n");
			free(url);
		} else logmsg(LOG_NOISY, 1, "Generic malware URL assembled: %s\n", url);

		if (((l_ip = strdup(inet_ntoa(*(struct in_addr*)&(attack->a_conn.l_addr)))) == NULL) ||
		    ((r_ip = strdup(inet_ntoa(*(struct in_addr*)&(attack->a_conn.r_addr)))) == NULL)) {
			logmsg(LOG_ERR, 1, "Error - Unable to allocate memory: %s.\n", strerror(errno));
			free(url);
			return(-1);
		}
		if (snprintf(query, MAX_SQL_BUFFER, "SELECT malware.sensor_honeytrap_add_sample('%s', '%s', '%s', '%s', '%s', '%s', %d, %d, '%s')",
			mem_md5sum(attack->download->dl_payload.data, attack->download->dl_payload.size),
			"mysensor", "malware", url, inet_ntoa(*(struct in_addr*)&(attack->a_conn.l_addr)),
			inet_ntoa(*(struct in_addr*)&(attack->a_conn.r_addr)), attack->a_conn.l_port,
			attack->download->r_port, esc_bytea) >= MAX_SQL_BUFFER) {
			logmsg(LOG_ERR, 1, "Error - Could not save attack: SQL query exceeds maximum size (increase MAX_SQL_BUFFER and recompile).\n");
				free(url);
				free(query);
				return(-1);
			}
		free(url);

		if (PQresultStatus(res = PQexec(db_connection, query)) != PGRES_TUPLES_OK) {
			logmsg(LOG_ERR, 1, "Database error - Malware submission failed: %s.\n", PQerrorMessage(db_connection));
			PQclear(res);
			db_disconnect();
			free(query);
			return(-1);
		}
		free(query);
		PQfreemem(esc_bytea);
		logmsg(LOG_NOISY, 1, "Attack database (Postgres) - Malware saved.\n");

		/* get instance number for reference within attack_string record */
		mw_inst = atoi(PQgetvalue(res, 0, PQfnumber(res, "sensor_honeytrap_add_sample")));

		PQclear(res);    
	}


	/* upload attack */
	if (attack->a_conn.payload.size > 0) {
		if ((query = malloc(MAX_SQL_BUFFER + 1)) == NULL) {
			logmsg(LOG_ERR, 1, "Error - Unable to allocate memory: %s.\n", strerror(errno));
			return(-1);
		}
		memset(query, 0, MAX_SQL_BUFFER + 1);

		/* escape byte data to prevent sql injection */    
		if ((esc_bytea = PQescapeByteaConn(db_connection, attack->a_conn.payload.data, attack->a_conn.payload.size, &length)) == NULL) {
			logmsg(LOG_ERR, 1, "Database error - Could not escape malware binary string: %s.\n", PQerrorMessage(db_connection));
			db_disconnect();
			free(query);
			return(-1);
		}

		starttime	= (char *) malloc(40 * sizeof(char));
		endtime		= (char *) malloc(40 * sizeof(char));
		strftime(starttime, 40, "%Y-%m-%d %T %Z", localtime(&attack->start_time));
		strftime(endtime, 40, "%Y-%m-%d %T %Z", localtime(&attack->end_time));

		if(attack->dl_count) {
			if (snprintf(query, MAX_SQL_BUFFER,
				"SELECT attacks.honeytrap_add_attack_string('%s'::varchar, %d::integer, '%s'::timestamptz, '%s'::timestamptz, " \
				"'%s'::inet, %d::integer, '%s'::inet, %d::integer, %d, %d::smallint, '%s'::inet, %d::integer, '%s'::bytea)",
				mem_md5sum(attack->a_conn.payload.data, attack->a_conn.payload.size),
//				mw_inst,
				0,
				starttime,
				endtime,
				inet_ntoa(*(struct in_addr*)attack->a_conn.r_addr),
				attack->a_conn.r_port,
				inet_ntoa(*(struct in_addr*)attack->a_conn.l_addr),
				attack->a_conn.l_port,
				attack->a_conn.protocol,
				attack->op_mode,
				inet_ntoa(*(struct in_addr*)&(attack->p_conn.r_addr)),
				attack->p_conn.r_port,
				esc_bytea) >= MAX_SQL_BUFFER) {
					logmsg(LOG_ERR, 1, "Error - Could not save attack: SQL query exceeds maximum size (increase MAX_SQL_BUFFER and recompile).\n");
					free(query);
					return(-1);
				}
		} else {
			if (snprintf(query, MAX_SQL_BUFFER,
				"SELECT attacks.honeytrap_add_attack_string('%s'::varchar, %d::integer, '%s'::timestamptz, '%s'::timestamptz, " \
				"'%s'::inet, %d::integer, '%s'::inet, %d::integer, %d, %d::smallint, '%s'::inet, %d::integer, '%s'::bytea)",
				mem_md5sum(attack->a_conn.payload.data, attack->a_conn.payload.size),
//				mw_inst,
				0,
				starttime,
				endtime,
				inet_ntoa(*(struct in_addr*)&(attack->a_conn.r_addr)),
				attack->a_conn.r_port,
				inet_ntoa(*(struct in_addr*)&(attack->a_conn.l_addr)),
				attack->a_conn.l_port,
				attack->a_conn.protocol,
				attack->op_mode,
				inet_ntoa(*(struct in_addr*)&(attack->p_conn.r_addr)),
				attack->p_conn.r_port,
				esc_bytea) >= MAX_SQL_BUFFER) {
					logmsg(LOG_ERR, 1, "Error - Could not save attack: SQL query exceeds maximum size (increase MAX_SQL_BUFFER and recompile).\n");
					free(query);
					return(-1);
				}
		}

		if (PQresultStatus(res = PQexec(db_connection, query)) != PGRES_TUPLES_OK) {
			logmsg(LOG_ERR, 1, "Database error - Attack submission failed: %s.\n", PQerrorMessage(db_connection));
			PQclear(res);
			db_disconnect();
			free(query);
			return(-1);
		}

		logmsg(LOG_NOISY, 1, "Attack database (Postgres) - Attack saved.\n");
		free(starttime);
		free(endtime);

		PQfreemem(esc_bytea);
		PQclear(res);
		free(query);
	}

	/* end transaction and disconnect */
	if (PQresultStatus(res = PQexec(db_connection, "END")) != PGRES_COMMAND_OK) {
		logmsg(LOG_ERR, 1, "Database error - END command failed: %s.\n", PQerrorMessage(db_connection));
		PQclear(res);
		db_disconnect();
		return(-1);
	}

	PQclear(res);
	db_disconnect();
	return(0);
}
