/* htm_magicPE.c
 * Copyright (C) 2008-2015 Tillmann Werner <tillmann.werner@gmx.de>
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
 *   This module handles an attack string as download if its
 *   file(1) signature sais it's a portable executable.
 *   This is useful for malware submission.
 */

#include <errno.h>
#include <magic.h>
#include <string.h>
#include <stdlib.h>

#include <honeytrap.h>
#include <logging.h>
#include <plughook.h>
#include <readconf.h>
#include <signals.h>

#include "htm_magicPE.h"

const char module_name[]="magicPE";
const char module_version[]="1.0.1";

magic_t		magicdb;


void plugin_config(void) {
	return;
}

void plugin_init(void) {
	if (((magicdb = magic_open( MAGIC_NO_CHECK_APPTYPE |
				    MAGIC_NO_CHECK_ASCII |
				    MAGIC_NO_CHECK_ELF |
				    MAGIC_NO_CHECK_FORTRAN |
				    MAGIC_NO_CHECK_TROFF))
				    == NULL) || (magic_load(magicdb, NULL) == -1)) {
		fprintf(stderr, "  Error - Unable to open magic database: %s.\n", magic_error(magicdb));
		exit(EXIT_FAILURE);
	}

	plugin_register_hooks();

	return;
}

void plugin_unload(void) {
	unhook(PPRIO_ANALYZE, module_name, "check_magic_string");
	magic_close(magicdb);
	return;
}

void plugin_register_hooks(void) {
	logmsg(LOG_DEBUG, 1, "    Plugin %s: Registering hooks.\n", module_name);
	add_attack_func_to_list(PPRIO_ANALYZE, module_name, "check_magic_string", (void *) check_magic_string);

	return;
}

int check_magic_string(Attack *attack) {
	const char *type = magic_buffer(magicdb, attack->a_conn.payload.data, attack->a_conn.payload.size);

	// check if it contains "MS-DOS executable" and if so, handle it as download
	if (strstr(type, "MS-DOS executable") != NULL) {
		logmsg(LOG_INFO, 1, "magicPE - Treating attack as malware because of type '%s'\n", type);
		add_download("raw",
			attack->a_conn.protocol,
			attack->a_conn.r_addr,
			attack->a_conn.r_port,
			NULL, NULL, NULL, NULL,
			attack->a_conn.payload.data,
			attack->a_conn.payload.size,
			attack);

		logmsg(LOG_NOTICE, 1, "magicPE - Attack string attached as download to attack record.\n");
	}

	return 0;
}
