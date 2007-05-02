/* htm_aSavePostgres.h
 * Copyright (C) 2007 Tillman Werner <tillmann.werner@gmx.de>,
 *                    Christoph Fuchs <christoph.fuchs@gmx.de>
 *
 * This file is free software; as a special exception the author gives
 * unlimited permission to copy and/or distribute it, with or without
 * modifications, as long as this notice is preserved.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
 * implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */

#ifdef USE_POSTGRES

#ifndef __HT_MODULE_ASAVEPOSTGRES_H
#define __HT_MODULE_ASAVEPOSTGRES_H 1

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <postgresql/libpq-fe.h>

#define MAX_SQL_BUFFER	10485760		// 10 MB
#define MAX_URI_SIZE	2048

const char	module_name[]		= "htm_aSavePostgres";
const char	module_version[]	= "0.2";

struct pg_conn	*db_connection;

/* use static values for now. should be taken from configuration file */
const char	*db_info = "port=5432 host=127.0.0.1 user=mwcollect password=mwcollect dbname=mwcollect2";

void plugin_init(void);
void plugin_unload(void);
void plugin_register_hooks(void);

int db_submit(Attack *attack);
int db_connect(void);
void db_disconnect(void);
char *build_url(struct s_download *download);

#endif

#endif
