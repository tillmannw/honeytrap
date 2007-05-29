/* htm_SavePostgres.c
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
 *   This honeytrap module submits recorded attacks to a PostgreSQL database.
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
#include <libpq-fe.h>

#include <logging.h>
#include <honeytrap.h>
#include <attack.h>
#include <plughook.h>
#include <readconf.h>
#include <conftree.h>
#include <md5.h>
#include <sha512.h>
#include <ip.h>

#include "htm_SavePostgres.h"

const char	module_name[]		= "SavePostgres";
const char	module_version[]	= "0.4.0";

static const char *config_keywords[] = {
	"db_host",
	"db_port",
	"db_name",
	"db_user",
	"db_pass"
};

struct pg_conn	*db_connection;
char		*db_host = NULL,
		*db_port = NULL,
		*db_name = NULL,
		*db_user = NULL,
		*db_pass = NULL,
		*db_info = NULL;

#define MAX_SQL_BUFFER	10485760		// 10 MB
#define MAX_URI_SIZE	2048


void plugin_init(void) {
	/* TODO: register sensor in db, if not existent */
	plugin_register_hooks();
	register_plugin_confopts(module_name, config_keywords, sizeof(config_keywords)/sizeof(char *));
	if (process_conftree(config_tree, config_tree, plugin_process_confopts, NULL) == NULL) {
		fprintf(stderr, "  Error - Unable to process configuration tree for plugin %s.\n", module_name);
		exit(EXIT_FAILURE);
	}
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

		if OPT_IS("db_host") {
			db_host = value;
		} else if OPT_IS("db_port") {
			db_port = value;
		} else if OPT_IS("db_name") {
			db_name = value;
		} else if OPT_IS("db_user") {
			db_user = value;
		} else if OPT_IS("db_pass") {
			db_pass = value;
		} else {
			fprintf(stderr, "  Error - Invalid configuration option for plugin %s: %s\n", module_name, node->keyword);
			exit(EXIT_FAILURE);
		}
	}
	return(node);
}


int db_connect(void) {
	int dbstr_len = 0;

	if (db_port == NULL) {
		/* use default PostgeSQL port */
		if ((db_port = strdup("5432")) == NULL) {
			logmsg(LOG_ERR, 1, "SavePostgres error - Unable to allocate memory: %s.\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
	}
	if (db_host == NULL) {
		logmsg(LOG_ERR, 1, "SavePostgres error - Database connection info is incomplete: Host missing.\n");
		return(-1);
	}
	if (db_name == NULL) {
		logmsg(LOG_ERR, 1, "SavePostgres error - Database connection info is incomplete: Database name missing.\n");
		return(-1);
	}
	if (db_user == NULL) {
		logmsg(LOG_ERR, 1, "SavePostgres error - Database connection info is incomplete: User missing.\n");
		return(-1);
	}
	if (db_pass == NULL) {
		logmsg(LOG_ERR, 1, "SavePostgres error - Database connection info is incomplete: Password missing.\n");
		return(-1);
	}

	/* set db info */
	dbstr_len = strlen(db_host)+strlen(db_port)+strlen(db_name)+strlen(db_user)+strlen(db_pass)+36;
	if ((db_info = malloc(dbstr_len)) == NULL) {
		logmsg(LOG_ERR, 1, "SavePostgres error - Unable to allocate memory: %s\n", strerror(errno));
		return(-1);
	}
	memset(db_info, 0, dbstr_len);
	if (snprintf(db_info, dbstr_len, "port=%s host=%s user=%s password=%s dbname=%s", db_port, db_host, db_user, db_pass, db_name) >= dbstr_len) {
		logmsg(LOG_ERR, 1, "SavePostgres error - Database connect string truncated: %s.\n", strerror(errno));
		return(-1);
	}

	/* connect to database */
	if (PQstatus(db_connection = PQconnectdb(db_info)) != CONNECTION_OK) {
		logmsg(LOG_ERR, 1, "SavePostgres error - Could not connect to database: %s.\n", PQerrorMessage(db_connection));
		PQfinish(db_connection);
		return(-1);
	}
	logmsg(LOG_NOISY, 1, "SavePostgres - Database connection established.\n");
	if (PQsetClientEncoding(db_connection, "UTF8") != 0) {
		logmsg(LOG_ERR, 1, "SavePostgres error - Could not set database character encoding to UTF8: %s.\n", PQerrorMessage(db_connection));
		PQfinish(db_connection);
		return(-1);
	}
	return(0);
}


void db_disconnect(void) {
	/* disconnect from database */
	PQfinish(db_connection);
	logmsg(LOG_NOISY, 1, "SavePostgres - Connection closed.\n");
	return;
}


char *build_uri(struct s_download *download) {
	char		*uri;		// generic malware URI format 'type://user:pass@path/to/file:port/protocol'

	if ((uri = malloc(MAX_URI_SIZE + 1)) == NULL) {
		logmsg(LOG_ERR, 1, "SavePostgres error - Unable to allocate memory: %s.\n", strerror(errno));
		return(NULL);
	}
	memset(uri, 0, MAX_URI_SIZE+1);

	logmsg(LOG_DEBUG, 1, "SavePostgres - Building generic malware resource URI.\n");

	/* should check for supported protocol types */
	if (!strlen(download->dl_type)) {
		logmsg(LOG_WARN, 1, "SavePostgres warning - Could not build URI: Unknown protocol type.\n");
		return(NULL);
	}
	logmsg(LOG_DEBUG, 1, "Postgres client - Adding Type to URI: %s\n",download->dl_type);
	snprintf(uri + strlen(uri), strlen(download->dl_type) + 4, "%s://", download->dl_type);

	if(strlen(download->user)) {
		logmsg(LOG_NOISY, 1, "Postgres client - Adding user and pass to URI: %s:%s\n", download->user, download->pass);
		snprintf(uri + strlen(uri), strlen(download->user) + strlen(download->pass) + 3, "%s:%s@", download->user, download->pass);
	}

	logmsg(LOG_NOISY, 1, "SavePostgres - Adding host to URI: %s\n", inet_ntoa(*(struct in_addr*)&download->r_addr));
	strncat(uri, inet_ntoa(*(struct in_addr*)&download->r_addr), strlen(inet_ntoa(*(struct in_addr*)&download->r_addr)));

	if (download->filename) {
		logmsg(LOG_NOISY, 1, "SavePostgres - Adding filename to URI: %s\n", download->filename);
		snprintf(uri + strlen(uri), strlen(download->filename) + 2, "/%s", download->filename);
	}

	if (download->r_port) {
		logmsg(LOG_NOISY, 1, "SavePostgre - Adding port to URI: %d\n", download->r_port);
		snprintf(uri + strlen(uri), 7, ":%d/", download->r_port);
		strcat(uri + strlen(uri), PROTO(download->protocol));
	}


	return(uri);
}


int db_submit(Attack *attack) {
	PGresult	*res;
	char		*query, *starttime, *endtime, *uri, *l_ip, *r_ip;
	u_char		*esc_bytea;
	int		mw_inst = -1;
	size_t		length;

	/* no data - nothing todo */
	if ((attack->a_conn.payload.size == 0) || (attack->a_conn.payload.data == NULL)) {
		logmsg(LOG_DEBUG, 1, "SavePostgres - No data received, nothing to save.\n");
		return(0);
	}

	logmsg(LOG_DEBUG, 1, "SavePostgres - Connecting to database.\n");
	if (db_connect() != 0) return(-1);


	/* Start a transaction block */
	if (PQresultStatus(res = PQexec(db_connection, "BEGIN")) != PGRES_COMMAND_OK) {
		logmsg(LOG_ERR, 1, "SavePostgres error - BEGIN command failed: %s.\n", PQerrorMessage(db_connection));
		PQclear(res);
		db_disconnect();
		return(-1);
	}
	PQclear(res);


	/* upload malware */
	if (attack->dl_count) {
		if ((query = malloc(MAX_SQL_BUFFER + 1)) == NULL) {
			logmsg(LOG_ERR, 1, "SavePostgres error - Unable to allocate memory: %s.\n", strerror(errno));
			return(-1);
		}

		/* check if sample already exists */
		memset(query, 0, MAX_SQL_BUFFER + 1);
		if (snprintf(query, MAX_SQL_BUFFER, "SELECT mwcollect.sensor_exists_sample('%s', '%s');", 
			mem_sha512sum(attack->download->dl_payload.data, attack->download->dl_payload.size),
			mem_md5sum(attack->download->dl_payload.data, attack->download->dl_payload.size)) >= MAX_SQL_BUFFER) {
			logmsg(LOG_ERR, 1, "SavePostgres error - Could not check if sample exists: SQL query exceeds maximum size (increase MAX_SQL_BUFFER and recompile).\n");
			free(query);
			return(-1);
		}
		if (PQresultStatus(res = PQexec(db_connection, query)) != PGRES_TUPLES_OK) {
			logmsg(LOG_ERR, 1, "SavePostgres error - Test for malware existance failed: %s.\n", PQerrorMessage(db_connection));
			PQclear(res);
			db_disconnect();
			free(query);
			return(-1);
		}
		if (*PQgetvalue(res, 0, 0) == 't') {
			logmsg(LOG_NOISY, 1, "SavePostgres - Malware sample exists in database, increasing counter.\n");
		} else {
			/* escape byte data to prevent sql injection */
			if ((esc_bytea = PQescapeByteaConn(db_connection, attack->download->dl_payload.data,
							   attack->download->dl_payload.size, &length)) == NULL) {
				logmsg(LOG_ERR, 1, "SavePostgres error - Could not escape attack string: %s.\n", PQerrorMessage(db_connection));
				PQclear(res);
				db_disconnect();
				free(query);
				return(-1);
			}

			if ((uri = build_uri(attack->download)) == NULL) {
				logmsg(LOG_WARN, 1, "SavePostgres warning - Unable to build generic malware URI.\n");
				free(uri);
			} else logmsg(LOG_NOISY, 1, "SavePostgres - Generic malware URI assembled: %s\n", uri);

			if (((l_ip = strdup(inet_ntoa(*(struct in_addr*)&(attack->a_conn.l_addr)))) == NULL) ||
			    ((r_ip = strdup(inet_ntoa(*(struct in_addr*)&(attack->a_conn.r_addr)))) == NULL)) {
				logmsg(LOG_ERR, 1, "SavePostgres error - Unable to allocate memory: %s.\n", strerror(errno));
				free(uri);
				return(-1);
			}
			memset(query, 0, MAX_SQL_BUFFER + 1);
//			if (snprintf(query, MAX_SQL_BUFFER, "SELECT attacks.sensor_honeytrap_add_sample('%s', '%s', '%s', '%s', '%s', '%s', %d, %d, '%s')",
			if (snprintf(query, MAX_SQL_BUFFER, "SELECT mwcollect.sensor_add_sample('%s', '%s', '%s', '%s', '%s', '%s')",
				mem_md5sum(attack->download->dl_payload.data, attack->download->dl_payload.size),
				mem_sha512sum(attack->download->dl_payload.data, attack->download->dl_payload.size),
				esc_bytea,
//				"honeytrap-default",
//				"dynamic-generic",
				inet_ntoa(*(struct in_addr*)&(attack->a_conn.l_addr)),
				inet_ntoa(*(struct in_addr*)&(attack->a_conn.r_addr)),
				uri
//				attack->a_conn.l_port,
//				attack->download->r_port,
				) >= MAX_SQL_BUFFER) {
				logmsg(LOG_ERR, 1, "SavePostgres error - Could not save malware: SQL query exceeds maximum size (increase MAX_SQL_BUFFER and recompile).\n");
				free(uri);
				free(query);
				return(-1);
			}
			free(uri);

			if (PQresultStatus(res = PQexec(db_connection, query)) != PGRES_TUPLES_OK) {
				logmsg(LOG_ERR, 1, "SavePostgres error - Malware submission failed: %s.\n", PQerrorMessage(db_connection));
				logmsg(LOG_DEBUG, 1, "SavePostgres - Query was: %s.\n", query);
				PQclear(res);
				db_disconnect();
				free(query);
				return(-1);
			}
			free(query);
			PQfreemem(esc_bytea);
			logmsg(LOG_NOISY, 1, "SavePostgres - Malware saved.\n");

			/* get instance number for reference within attack_string record */
//			mw_inst = atoi(PQgetvalue(res, 0, PQfnumber(res, "sensor_honeytrap_add_sample")));
			mw_inst = atoi(PQgetvalue(res, 0, PQfnumber(res, "sensor_add_sample")));

			PQclear(res);    
		}
	}


	/* upload attack */
	if (attack->a_conn.payload.size > 0) {
		if ((query = malloc(MAX_SQL_BUFFER + 1)) == NULL) {
			logmsg(LOG_ERR, 1, "SavePostgres error - Unable to allocate memory: %s.\n", strerror(errno));
			return(-1);
		}
		memset(query, 0, MAX_SQL_BUFFER + 1);

		/* escape byte data to prevent sql injection */    
		if ((esc_bytea = PQescapeByteaConn(db_connection, attack->a_conn.payload.data, attack->a_conn.payload.size, &length)) == NULL) {
			logmsg(LOG_ERR, 1, "SavePostgres error - Could not escape malware binary string: %s.\n", PQerrorMessage(db_connection));
			db_disconnect();
			free(query);
			return(-1);
		}

		starttime	= (char *) malloc(40 * sizeof(char));
		endtime		= (char *) malloc(40 * sizeof(char));
		strftime(starttime, 40, "%Y-%m-%d %T %Z", localtime(&attack->start_time));
		strftime(endtime, 40, "%Y-%m-%d %T %Z", localtime(&attack->end_time));


/* FIXME: link samples to attacks */
/*
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
					logmsg(LOG_ERR, 1, "SavePostgres error - Could not save attack: SQL query exceeds maximum size (increase MAX_SQL_BUFFER and recompile).\n");
					free(query);
					return(-1);
				}
		} else {
*/
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
					logmsg(LOG_ERR, 1, "SavePostgres error - Could not save attack: SQL query exceeds maximum size (increase MAX_SQL_BUFFER and recompile).\n");
					free(query);
					return(-1);
				}
//		}

		if (PQresultStatus(res = PQexec(db_connection, query)) != PGRES_TUPLES_OK) {
			logmsg(LOG_ERR, 1, "SavePostgres error - Attack submission failed: %s.\n", PQerrorMessage(db_connection));
			PQclear(res);
			db_disconnect();
			free(query);
			return(-1);
		}

		logmsg(LOG_NOISY, 1, "SavePostgres - Attack saved.\n");
		free(starttime);
		free(endtime);

		PQfreemem(esc_bytea);
		PQclear(res);
		free(query);
	}

	/* end transaction and disconnect */
	if (PQresultStatus(res = PQexec(db_connection, "END")) != PGRES_COMMAND_OK) {
		logmsg(LOG_ERR, 1, "SavePostgres error - END command failed: %s.\n", PQerrorMessage(db_connection));
		PQclear(res);
		db_disconnect();
		return(-1);
	}

	PQclear(res);
	db_disconnect();
	return(0);
}
