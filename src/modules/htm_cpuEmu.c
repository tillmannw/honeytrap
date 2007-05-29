/* htm_cpuEmu.c
 * Copyright (C) 2007 Tillmann Werner <tillmann.werner@gmx.de>
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
 *   This honeytrap module tries to find a shellcode within an attack string
 *   and the runs this code in a libemu-based x86 CPU emulation.
 *   libemu was written by Paul Baecher and Markus Koetter.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/stat.h>
#include <netdb.h>
#include <sys/socket.h>
#include <stdio.h>

#include <honeytrap.h>
#include <logging.h>
#include <plughook.h>
#include <util.h>
#include <md5.h>

#include "htm_cpuEmu.h"

#include <emu/emu.h>
#include <emu/emu_track.h>
#include <emu/emu_memory.h>
#include <emu/emu_cpu.h>
#include <emu/environment/win32/emu_env_w32.h>
//#include <emu/environment/win32/emu_env_w32_dll.h>
//#include <emu/environment/win32/emu_env_w32_dll_export.h>
#include <emu/emu_getpc.h>

#include "emu/emu_shellcode.h"


void plugin_init(void) {
	plugin_register_hooks();
	return;
}

void plugin_unload(void) {
	unhook(PPRIO_ANALYZE, module_name, "find_shellcode");
	return;
}

void plugin_register_hooks(void) {
	DEBUG_FPRINTF(stdout, "    Plugin %s: Registering hooks.\n", module_name);
	add_attack_func_to_list(PPRIO_ANALYZE, module_name, "find_shellcode", (void *) find_shellcode);

	return;
}

int find_shellcode(Attack *attack) {
	struct emu *e = NULL;
	int32_t offset;

	/* no data - nothing todo */
	if ((attack->a_conn.payload.size == 0) || (attack->a_conn.payload.data == NULL)) {
		logmsg(LOG_DEBUG, 1, "CPU emulation - No data received, won't start emulation.\n");
		return(0);
	}

	logmsg(LOG_DEBUG, 1, "CPU emulation - Parsing attack string (%d bytes) for shellcode.\n", attack->a_conn.payload.size);

	if ((e = emu_new()) == NULL) {
		logmsg(LOG_ERR, 1, "cpuEmu Error - Unable to initialize virtual CPU.\n");
		return(-1);
	}

	logmsg(LOG_NOISY, 1, "CPU emulation - Analyzing %d bytes.\n", attack->a_conn.payload.size);

	if ((offset = emu_shellcode_test(e, (u_char *) attack->a_conn.payload.data, attack->a_conn.payload.size)) >= 0) {
		logmsg(LOG_NOISY, 1, "CPU emulation - Possible start of shellcode detected at offset %u.\n", offset);
		emu_free(e);
		return(1);
	}

	emu_free(e);
	return(0);
}
