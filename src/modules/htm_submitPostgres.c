/* htm_submitPostgres.c
 * Copyright (C) 2007-2015 Tillmann Werner <tillmann.werner@gmx.de>,
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

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <libpq-fe.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <logging.h>
#include <honeytrap.h>
#include <attack.h>
#include <plughook.h>
#include <readconf.h>
#include <conftree.h>
#include <md5.h>
#include <sha512.h>
#include <tcpip.h>

#include "htm_submitPostgres.h"

const char	module_name[]		= "submitPostgres";
const char	module_version[]	= "1.0.1";

static const char *config_keywords[] = {
	"sensor_id",
	"db_host",
	"db_port",
	"db_name",
	"db_user",
	"db_pass"
};

struct pg_conn	*db_connection;
char		*sensor_id = NULL,
		*db_host = NULL,
		*db_port = NULL,
		*db_name = NULL,
		*db_user = NULL,
		*db_pass = NULL,
		*db_info = NULL;


void plugin_config(void) {
	register_plugin_confopts(module_name, config_keywords, sizeof(config_keywords)/sizeof(char *));
	if (process_conftree(config_tree, config_tree, plugin_process_confopts, NULL) == NULL) {
		fprintf(stderr, "  Error - Unable to process configuration tree for plugin %s.\n", module_name);
		exit(EXIT_FAILURE);
	}
	return;
}

void plugin_init(void) {
	// check if all needed options are given
	if (db_host == NULL) {
		fprintf(stderr, "  SubmitPostgres Error - Incomplete configuration: Database host missing.\n");
		exit(EXIT_FAILURE);
	}
	if (db_name == NULL) {
		fprintf(stderr, "  SubmitPostgres Error - Incomplete configuration: Database name missing.\n");
		exit(EXIT_FAILURE);
	}
	if (db_user == NULL) {
		fprintf(stderr, "  SubmitPostgres Error - Incomplete configuration: Database user missing.\n");
		exit(EXIT_FAILURE);
	}
	if (db_pass == NULL) {
		fprintf(stderr, "  SubmitPostgres Error - Incomplete configuration: Database password missing.\n");
		exit(EXIT_FAILURE);
	}
	if (sensor_id == NULL) {
		fprintf(stderr, "  SubmitPostgres Error - Incomplete configuration: Sensor ID missing.\n");
		exit(EXIT_FAILURE);
	}

	plugin_register_hooks();

	return;
}


void plugin_unload(void) {
	unhook(PPRIO_SAVEDATA, module_name, "db_submit");
	return;
}


void plugin_register_hooks(void) {
	logmsg(LOG_DEBUG, 1, "    Plugin %s: Registering hooks.\n", module_name);
	add_attack_func_to_list(PPRIO_SAVEDATA, module_name, "db_submit", (void *) db_submit);

	return;
}


conf_node *plugin_process_confopts(conf_node *tree, conf_node *node, void *opt_data) {
	char		*value = NULL;
	conf_node	*confopt = NULL;

	if ((confopt = check_keyword(tree, node->keyword)) == NULL) return NULL;

	while (node->val) {
		if ((value = malloc(node->val->size+1)) == NULL) {
			fprintf(stderr, "  SubmitPostgres Error - Unable to allocate memory: %s.", strerror(errno));
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
		} else if OPT_IS("sensor_id") {
			sensor_id = value;
		} else {
			fprintf(stderr, "  SubmitPostgres Error - Invalid configuration option for plugin %s: %s\n", module_name, node->keyword);
			exit(EXIT_FAILURE);
		}
	}

	return node;
}


int db_connect(void) {
	if (db_port == NULL) {
		// use default PostgeSQL port
		if ((db_port = strdup("5432")) == NULL) {
			logmsg(LOG_ERR, 1, "SubmitPostgres Error - Unable to allocate memory: %s.\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

	if (asprintf(&db_info, "port=%s host=%s user=%s password=%s dbname=%s", db_port, db_host, db_user, db_pass, db_name) == -1) {
		logmsg(LOG_ERR, 1, "SubmitPostgres Error - Unable to allocate memory: %s.\n", strerror(errno));
		return -1;
	}

	// connect to database
	if (PQstatus(db_connection = PQconnectdb(db_info)) != CONNECTION_OK) {
		logmsg(LOG_ERR, 1, "SubmitPostgres Error - Could not connect to database: %s.\n", PQerrorMessage(db_connection));
		PQfinish(db_connection);
		return -1;
	}
	logmsg(LOG_DEBUG, 1, "SubmitPostgres - Database connection established.\n");
	if (PQsetClientEncoding(db_connection, "UTF8") != 0) {
		logmsg(LOG_ERR, 1, "SubmitPostgres Error - Could not set database character encoding to UTF8: %s.\n", PQerrorMessage(db_connection));
		PQfinish(db_connection);
		return -1;
	}
	return 0;
}


void db_disconnect(void) {
	// disconnect from database
	PQfinish(db_connection);
	free(db_info);
	logmsg(LOG_DEBUG, 1, "SubmitPostgres - Database connection closed.\n");
	return;
}


char *build_uri(struct s_download *download) {
	char *uri;	// generic malware URI format 'type://user:pass@path/to/file:port/protocol'

	logmsg(LOG_DEBUG, 1, "SubmitPostgres - Assembling generic malware URI.\n");

	if (download->uri) return strdup(download->uri);

	if (download->dl_type == NULL) {
		logmsg(LOG_WARN, 1, "SubmitPostgres Warning - Could not build URI: Unknown protocol type.\n");
		return NULL;
	}

	if (asprintf(&uri, "%s://%s:%s@%s:%u/%s:%s",
		download->dl_type,
		download->user,
		download->pass,
		inet_ntoa(*(struct in_addr*)&download->r_addr),
		download->r_port,
		PROTO(download->protocol),
		download->filename) == -1) {
		logmsg(LOG_ERR, 1, "SubmitPostgres Error - Unable to allocate memory: %s.\n", strerror(errno));
		return NULL;
	}

	return uri;
}


int db_submit(Attack *attack) {
	PGresult	*res;
	char		*query, *starttime, *endtime, *url, *l_ip, *r_ip;
	u_char		*esc_bytea;
	int		attack_inst = -1, i;
	size_t		length;
	char		*locationID = NULL;

	// no data - nothing to do
	if ((attack->a_conn.payload.size == 0) || (attack->a_conn.payload.data == NULL)) {
		logmsg(LOG_DEBUG, 1, "SubmitPostgres - No data received, nothing to save.\n");
		return 0;
	}


	// connect to postgres database
	logmsg(LOG_DEBUG, 1, "SubmitPostgres - Connecting to database.\n");
	if (db_connect() != 0) {
		logmsg(LOG_ERR, 1, "SubmitPostgres Error - Unable to connect to database: %s.\n", PQerrorMessage(db_connection));
		return -1;
	}
	logmsg(LOG_DEBUG, 1, "SubmitPostgres - Connection to database established.\n");


	// start a transaction block
	if (PQresultStatus(res = PQexec(db_connection, "BEGIN")) != PGRES_COMMAND_OK) {
		logmsg(LOG_ERR, 1, "SubmitPostgres Error - BEGIN command failed: %s.\n", PQerrorMessage(db_connection));
		PQclear(res);
		db_disconnect();
		return -1;
	}
	PQclear(res);


	// submit attack data
	if (attack->a_conn.payload.size > 0 && attack->a_conn.payload.data != NULL) {
	  logmsg(LOG_DEBUG, 1, "SubmitPostgres - Submitting attack string.\n");
		// escape attack string
		if ((esc_bytea = PQescapeByteaConn(db_connection, attack->a_conn.payload.data, attack->a_conn.payload.size, &length)) == NULL) {
			logmsg(LOG_ERR, 1, "Database error - Could not escape attack string: %s.\n", PQerrorMessage(db_connection));
			db_disconnect();
			return -1;
		}

		if (((starttime = calloc(1, 40)) == NULL) || ((endtime = calloc(1, 40)) == NULL)) {
			logmsg(LOG_ERR, 1, "SubmitPostgres Error - Unable to allocate memory: %s.\n", strerror(errno));
			db_disconnect();
			return -1;
		}
		if ((strftime(starttime, 40, "%Y-%m-%d %T %Z", localtime(&attack->start_time)) == 0) || 
		    (strftime(endtime, 40, "%Y-%m-%d %T %Z", localtime(&attack->end_time)) == 0)) {
			logmsg(LOG_ERR, 1, "SubmitPostgres Error - Unable to convert timestamps.\n");
			db_disconnect();
			return -1;
		}

		char *src_ip, *dst_ip, *fwd_ip;
		if (((src_ip = strdup(inet_ntoa(*(struct in_addr*)&attack->a_conn.r_addr))) == NULL) ||
		    ((dst_ip = strdup(inet_ntoa(*(struct in_addr*)&attack->a_conn.l_addr))) == NULL) ||
		    ((fwd_ip = strdup(inet_ntoa(*(struct in_addr*)&attack->p_conn.r_addr))) == NULL)) {
			logmsg(LOG_ERR, 1, "SubmitPostgres Error - Unable to allocate memory: %s.\n", strerror(errno));
			db_disconnect();
			free(query);
			return -1;
		}
		
		if (asprintf(&query,
			     "SELECT attacks.honeytrap_add_attack_string('%s'::varchar, %d::integer, '%s'::timestamptz, '%s'::timestamptz, '%s'::inet, %s::integer, %d::integer, '%s'::inet, %d::integer, %d, %d::smallint, '%s'::inet, %d::integer, E'%s'::bytea)",
			     attack->a_conn.payload.md5sum,
			     0,
			     starttime,
			     endtime,
			     src_ip,
			     locationID,
			     attack->a_conn.r_port,
			     dst_ip,
			     attack->a_conn.l_port,
			     attack->a_conn.protocol,
			     attack->op_mode,
			     fwd_ip,
			     attack->p_conn.r_port,
			     esc_bytea) == -1) {
			logmsg(LOG_ERR, 1, "SubmitPostgres Error - Could not create SQL query: %s.\n", strerror(errno));
			return -1;
		}

		if (PQresultStatus(res = PQexec(db_connection, query)) != PGRES_TUPLES_OK) {
			logmsg(LOG_ERR, 1, "SubmitPostgres Error - Attack submission failed: %s.\n", PQerrorMessage(db_connection));
			PQclear(res);
			db_disconnect();
			free(query);
			return -1;
		}
		
		logmsg(LOG_NOISY, 1, "SubmitPostgres - Attack saved.\n");
		
		// get instance number for reference within honeytrap_instance record
		logmsg(LOG_DEBUG, 1, "SubmitPostgres - Retrieving attack ID.\n");
		attack_inst = atoi(PQgetvalue(res, 0, PQfnumber(res, "honeytrap_add_attack_string")));
		logmsg(LOG_DEBUG, 1, "SubmitPostgres - Attack ID: %d.\n", attack_inst);
      
		free(starttime);
		free(endtime);
		
		PQfreemem(esc_bytea);
		PQclear(res);
		free(query);

		// upload malware
		if (attack->dl_count) {
			logmsg(LOG_DEBUG, 1, "SubmitPostgres - Submitting malware to database (%d files).\n", attack->dl_count);

			for(i=0;i<attack->dl_count;i++) {
				// escape data
				if ((esc_bytea = PQescapeByteaConn(db_connection, attack->download[i].dl_payload.data, attack->download[i].dl_payload.size, &length)) == NULL) {
					logmsg(LOG_ERR, 1, "SubmitPostgres Error - Could not escape malware binary string: %s.\n", PQerrorMessage(db_connection));
					PQclear(res);
					db_disconnect();
					free(query);
					return -1;
				}

				if ((url = build_uri(&attack->download[i])) == NULL) {
					logmsg(LOG_WARN, 1, "SubmitPostgres Warning - Unable to assemble generic malware URL.\n");
					free(url);
				} else logmsg(LOG_DEBUG, 1, "SubmitPostgres - Generic malware URL assembled: %s\n", url);

				if (((l_ip = strdup(inet_ntoa(*(struct in_addr*)&(attack->a_conn.l_addr)))) == NULL) ||
				    ((r_ip = strdup(inet_ntoa(*(struct in_addr*)&(attack->a_conn.r_addr)))) == NULL)) {
					logmsg(LOG_ERR, 1, "SubmitPostgres Error - Unable to allocate memory: %s.\n", strerror(errno));
					free(url);
					return -1;
				}
				if (asprintf(&query, "SELECT malware.sensor_honeytrap_add_sample('%s', '%s', %d, '%s', '%s', '%s', %d, %d, E'%s')",
					     attack->download[i].dl_payload.sha512sum,
					     sensor_id,
					     attack_inst,
					     url,
					     l_ip,
					     r_ip,
					     attack->a_conn.l_port,
					     attack->download->r_port,
					     esc_bytea) == -1) {
					logmsg(LOG_ERR, 1,
						"SubmitPostgres Error - Could not create SQL query: %s.\n", strerror(errno));
					free(url);
					return -1;
				}
				free(url);

				if (PQresultStatus(res = PQexec(db_connection, query)) != PGRES_TUPLES_OK) {
					logmsg(LOG_ERR, 1, "SubmitPostgres Error - Malware submission failed: %s.\n", PQerrorMessage(db_connection));
					PQclear(res);
					db_disconnect();
					free(query);
					return -1;
				}
				free(query);
				PQfreemem(esc_bytea);
				logmsg(LOG_NOISY, 1, "SubmitPostgres - Malware saved (%d/%d).\n", i+1, attack->dl_count);       		  
				PQclear(res);    
			}
		}

	}

	// end transaction and disconnect
	if (PQresultStatus(res = PQexec(db_connection, "END")) != PGRES_COMMAND_OK) {
		logmsg(LOG_ERR, 1, "SubmitPostgres Error - END command failed: %s.\n", PQerrorMessage(db_connection));
		PQclear(res);
		db_disconnect();
		return -1;
	}

	PQclear(res);
	db_disconnect();
	return 0;
}
