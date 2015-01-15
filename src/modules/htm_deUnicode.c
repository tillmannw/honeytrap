/* htm_deUnicode.c
 * Copyright (C) 2009-2015 Tillmann Werner <tillmann.werner@gmx.de>
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
 *   This honeytrap module performs a simple heuristic test for uniocde attack strings,
 *   decodes them into a new attack string and calls other plugins for it.
 */

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <attack.h>
#include <honeytrap.h>
#include <logging.h>
#include <plughook.h>

#include "htm_deUnicode.h"

const char module_name[]="deUnicode";
const char module_version[]="1.0.1";

void plugin_config(void) {
	return;
}

void plugin_init(void) {
	plugin_register_hooks();
	return;
}

void plugin_unload(void) {
	unhook(PPRIO_PREPROC, module_name, "deunicode");
	return;
}

void plugin_register_hooks(void) {
	logmsg(LOG_DEBUG, 1, "    Plugin %s: Registering hooks.\n", module_name);
	add_attack_func_to_list(PPRIO_PREPROC, module_name, "deunicode", (void *) deunicode);

	return;
}

int deunicode(Attack *attack) {
	Attack *dec_attack;
	u_char offset;
	size_t i, bytecnt[256], offcheck[256], data_len;


	// no data - nothing todo
	if ((attack->a_conn.payload.size == 0) || (attack->a_conn.payload.data == NULL)) {
		logmsg(LOG_DEBUG, 1, "deUnicode - No data received, nothing to decode.\n");
		return(0);
	}

	memset(bytecnt, 0, 256 * sizeof(size_t));
	memset(offcheck, 0, 256 * sizeof(size_t));

	for (i = 0; i < attack->a_conn.payload.size; ++i) {
		bytecnt[attack->a_conn.payload.data[i]]++;
		if (i%2) offcheck[attack->a_conn.payload.data[i]]++;
	}

	if (bytecnt[0] * 3 > attack->a_conn.payload.size) {
		logmsg(LOG_NOISY, 1, "deUnicode - Attack string seems to contain unicode encoded data, decoding it.\n");

		// if the array for every second byte, starting with 1, contains at least half of all 0-bytes,
		// we're correctly aligned, otherwise we have to use an offset of 1
		offset = offcheck[0] * 2 > bytecnt[0] ? 0 : 1;

		// half the size (+1) of the original attack string is sufficient as we skip every second byte
		data_len = attack->a_conn.payload.size >> 1;
		if ((attack->a_conn.payload.size % 2 == 1) && (offset == 0)) data_len++;

		if (((dec_attack = calloc(1, sizeof(Attack))) == NULL) ||
		    ((dec_attack->a_conn.payload.data = calloc(1, data_len)) == NULL)) {
			logmsg(LOG_ERR, 1, "deUnicode error - Unable to allocate memory: %s.\n", strerror(errno));
			return -1;
		}
		dec_attack->virtual = 1;
		dec_attack->a_conn.payload.size = data_len;

		for (i=0; i+offset < attack->a_conn.payload.size; i+=2)
			dec_attack->a_conn.payload.data[i>>1] = attack->a_conn.payload.data[i+offset];

		logmsg(LOG_NOISY, 1, "deUnicode - Processing decoded attack.\n");

		plughook_process_attack(funclist_attack_preproc, dec_attack);
		plughook_process_attack(funclist_attack_analyze, dec_attack);

		// assign possible downloads to the original attack,
		// this must happen before PPRIO_SAVE plugins are called
		reassign_downloads(attack, dec_attack);

//		plughook_process_attack(funclist_attack_savedata, dec_attack);
		plughook_process_attack(funclist_attack_postproc, dec_attack);

		del_attack(dec_attack);
	} else {
		logmsg(LOG_DEBUG, 1, "deUnicode - Attack string does not seem to be in unicode.\n");
		return 0;
	}
	return 1;
}
