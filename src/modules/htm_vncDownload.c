/* htm_vncDownload.c
 * Copyright (C) 2006 Tillmann Werner <tillmann.werner@gmx.de>
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
 *   This honeytrap module invokes wget (or other external tools) to perform
 *   http downloads triggerd by a VNC server exploit.
 */

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>

#include <logging.h>
#include <plughook.h>
#include <honeytrap.h>

#include "htm_vncDownload.h"

const char module_name[]="htm_vncDownload";
const char module_version[]="0.3";


void plugin_init(void) {
	plugin_register_hooks();
	return;
}

void plugin_unload(void) {
	unhook(PPRIO_ANALYZE, module_name, "cmd_parse_for_vnc");
	return;
}

void plugin_register_hooks(void) {
	DEBUG_FPRINTF(stdout, "    Plugin %s: Registering hooks.\n", module_name);
	add_attack_func_to_list(PPRIO_ANALYZE, module_name, "cmd_parse_for_vnc", (void *) cmd_parse_for_vnc);

	return;
}

int cmd_parse_for_vnc(Attack *attack) {
	int i=0, len = 0;
	char vnc_str[] = "RFB 003.008";
	char *readable_chars = NULL, *clean_str = NULL, *curchar = NULL, *cmd = NULL;
	FILE *f;

	logmsg(LOG_DEBUG, 1, "Checking for VNC session string in attack string.\n");

	/* no data, nothing to do */
	if ((attack->a_conn.payload.size == 0) || (attack->a_conn.payload.data == NULL)) return(1);

	/* parse for VNC session indicator - if found, search for url */
	if (memcmp(attack->a_conn.payload.data, vnc_str, strlen(vnc_str)) == 0) {
		logmsg(LOG_DEBUG, 1, "Found VNC session string, parsing attack string for HTTP URL.\n");
		for (i=strlen(vnc_str); i<attack->a_conn.payload.size; i++) {
			if (isprint(attack->a_conn.payload.data[i])) {
			       	if (isspace(attack->a_conn.payload.data[i])) break;
				if ((readable_chars = realloc(readable_chars, len+2)) == NULL) {
					logmsg(LOG_ERR, 1, "Error - Unable to allocate memory: %s.\n", strerror(errno));
					return(0);
				}
				readable_chars[len] = attack->a_conn.payload.data[i];
				readable_chars[len+1] = 0;
				len++;
			}
		}
		if (len) {
			/* piece together HTTP url from readable characters - really dirty */
			curchar = readable_chars;

			/* skip leading 'r's */
			for (i=0; i<strlen(readable_chars) && readable_chars[i] == 'r'; curchar++, i++);
			clean_str = curchar;
			
			/* cut trailing 'Q's */
			for (i=strlen(clean_str)-1; clean_str[i] == 'Q' && i>0; clean_str[i] = 0, i--);

			/* un-double chars */
			for (i=0; i<strlen(clean_str)-1; i++) 
				if (clean_str[i] == clean_str[i+1]) {
					memmove(&clean_str[i], &clean_str[i+1], strlen(&clean_str[i+1]));
					clean_str[strlen(clean_str)-1] = 0;
				}

			/* assemble wget download command and execute it */
			if (strstr(clean_str, "http://") == clean_str) {
				if ((cmd = malloc(strlen(clean_str)+19)) == NULL) {
					logmsg(LOG_ERR, 1, "Error - Unable to allocate memory: %s.\n", strerror(errno));
					return(0);
				}
				sprintf(cmd, "%s %s", "/usr/bin/wget -nv", clean_str);
				logmsg(LOG_DEBUG, 1, "Calling '%s'.\n", cmd);
				if ((f = popen(cmd, "r")) == NULL) {
					logmsg(LOG_ERR, 1, "Error - Cannot call download command: %s.\n", strerror(errno));
					return(0);
				}
				pclose(f);
				free(cmd);
			}
		}
		free(readable_chars);
	} else logmsg(LOG_DEBUG, 1, "No VNC session string found.\n");
	return(1);
}
