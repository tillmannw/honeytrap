/* htm_b64Decode.c
 * Copyright (C) 2006-2015 Tillmann Werner <tillmann.werner@gmx.de>
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
 *   This honeytrap module looks for base64-encoded parts in attacks, decodes
 *   them into a new attack string and calls other plugins for it.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <strings.h>
#include <stdio.h>

#include <attack.h>
#include <honeytrap.h>
#include <logging.h>
#include <plughook.h>

#include "htm_b64Decode.h"

const char module_name[]="b64Decode";
const char module_version[]="1.0.1";


void plugin_config(void) {
	return;
}

void plugin_init(void) {
	plugin_register_hooks();
	return;
}

void plugin_unload(void) {
	unhook(PPRIO_PREPROC, module_name, "b64_decode");
	return;
}

void plugin_register_hooks(void) {
	logmsg(LOG_DEBUG, 1, "    Plugin %s: Registering hooks.\n", module_name);
	add_attack_func_to_list(PPRIO_PREPROC, module_name, "b64_decode", (void *) b64_decode);

	return;
}

struct dec *decode(const char* code, u_int32_t len) {
	u_char ch, inbuf[3];
	u_int32_t charctr, bufctr, ign, eot, i;
	struct dec *ret;

	eot	= 0;
	ign	= 0;
	bufctr	= 0;

	if ((ret = (struct dec *) malloc(sizeof(struct dec))) == NULL) {
		logmsg(LOG_ERR, 1, "Base64 decoder error - Unable to allocate memory: %s.\n", strerror(errno));
		return(NULL);
	}
	ret->len	= 0;
	ret->str  = (u_char*) malloc(len*3/4+1);
	bzero(ret->str, len*3/4+1);

	for (i=0; i<len; i++) {
		ch = code[i];

		if (isupper(ch)) ch -= 'A';
		else if (islower(ch)) ch = ch - 'a' + 26;
		else if (isdigit(ch)) ch = ch - '0' + 52;
		else if (ch == '+') ch = 62;
		else if (ch == '=') eot = 1;
		else if (ch == '/') ch = 63;
		else ign = 1;

		if (!ign) {
			if (eot) {
				if (bufctr == 0) return(NULL);
				charctr = ((bufctr == 0) || (bufctr == 1)) ? 0 : 1;
				bufctr = 2;
			} else charctr = 2;

			inbuf[bufctr++] = ch;

			if (bufctr == 3) {
				bufctr = 0;

				ret->str[ret->len++] =  (inbuf[0] << 2) | ((inbuf[0] & 0x30) >> 4);
				if (charctr > 0) ret->str[ret->len++] =  ((inbuf[0] & 0x0F) << 4) | ((inbuf[1] & 0x3C) >> 2);
				if (charctr > 1) ret->str[ret->len++] =  ((inbuf[1] & 0x03) << 6) | (inbuf[2] & 0x3F);
			}
			if (eot) return(ret);
		}
	}
	return(ret);
}

int b64_decode(Attack *attack) {
	char *code, *astr;
	struct dec *decoded;
	Attack dec_attack;

	/* no data - nothing todo */
	if ((attack->a_conn.payload.size == 0) || (attack->a_conn.payload.data == NULL)) {
		logmsg(LOG_DEBUG, 1, "Base64 decoder - No data received, nothing to decode.\n");
		return(0);
	}

	logmsg(LOG_DEBUG, 1, "Base64 decoder - Searching for base64 encoded attack string.\n");

	/* zero-terminate attack string */
	if ((astr = (char *) malloc(attack->a_conn.payload.size+1)) == NULL) {
		logmsg(LOG_ERR, 1, "Error - Unable to allocate memory: %s.\n", strerror(errno));
		return(-1);
	}
	bzero(astr, attack->a_conn.payload.size+1);
	strncpy(astr, (char *) attack->a_conn.payload.data, attack->a_conn.payload.size);
	
	/* look for characteristic strings after which base64 encoded data starts */
	if (((code = (char *) strstr(astr, "Negotiate ")) != NULL)
	    /* add additional checks here
 	    || (code = strstr(astr, "[DUMMY_STRING]")) != NULL) */
	    ) {
		/* decode base64 code */
		logmsg(LOG_INFO, 1, "Base64 decoder - Encoded attack string found, trying to decode.\n");

		code += 10;
		if ((decoded = decode((char *)code, strlen(code))) != NULL) {
			/* base64 decoded, creating attack structure and call other plugins */
			logmsg(LOG_INFO, 1, "Calling plugins for decoded attack.\n");

			bzero(&dec_attack, sizeof(Attack));
			dec_attack.a_conn.payload.data = decoded->str;
			dec_attack.a_conn.payload.size = decoded->len;

			plughook_process_attack(funclist_attack_preproc, &dec_attack);
			plughook_process_attack(funclist_attack_analyze, &dec_attack);

			// assign possible downloads to the original attack,
			// this must happen before PPRIO_SAVE plugins are called
			reassign_downloads(attack, &dec_attack);

//			plughook_process_attack(funclist_attack_savedata, &dec_attack);
			plughook_process_attack(funclist_attack_postproc, &dec_attack);

			free(decoded->str);
		}
	} else {
		logmsg(LOG_DEBUG, 1, "Base64 decoder - No base64 encoded attack string found.\n");
		return(0);
	}
	return(1);
}
