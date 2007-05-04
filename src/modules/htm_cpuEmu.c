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
	logmsg(LOG_DEBUG, 1, "Parsing attack string (%d bytes) for shellcode.\n", attack->a_conn.payload.size);

	struct emu *e = emu_new();
	struct emu_cpu *cpu = emu_cpu_get(e);
	struct emu_memory *mem = emu_memory_get(e);
	struct emu_env_w32 *env = emu_env_w32_new(e);
	struct emu_track_and_source *et = emu_track_and_source_new();

	struct instr_test i_test;
	memset(&i_test, 0, sizeof(struct instr_test));

	if (env == 0) {
		logmsg(LOG_ERR, 1, "CPU emulation error - Unable to create win32 environment: %s.\n", emu_strerror(e));
		logmsg(LOG_ERR, 1, "CPU emulation error - strerror(emu_errno(e)): %s.\n", strerror(emu_errno(e)));
		return(-1);
	}

	bool found_good_candidate_after_getpc = false;

	logmsg(LOG_NOISY, 1, "CPU emulation - Analyzing %d bytes.\n", attack->a_conn.payload.size);

	uint32_t offset;
	for (offset=0; offset<attack->a_conn.payload.size && found_good_candidate_after_getpc == false; offset++) {
		if (emu_getpc_check(e, (uint8_t *)attack->a_conn.payload.data, attack->a_conn.payload.size, offset) == 1) {
			int j = 0;

			/* set registers to initial values */
			for (j = 0; j < 8; j++) emu_cpu_reg32_set(cpu,j ,i_test.in_state.reg[j]);

			/* set flags */
			emu_cpu_eflags_set(cpu, i_test.in_state.eflags);

			/* write code to offset */
			int static_offset = CODE_OFFSET;
			for (j = 0; j < attack->a_conn.payload.size; j++)
				emu_memory_write_byte(mem, static_offset+j, attack->a_conn.payload.data[j]);

			/* set eip to getpc code */
			emu_cpu_eip_set(emu_cpu_get(e), static_offset+offset);

			int ret = -1;
			int track = 0;

			/* run the code */
			for (j = 0; j < opts.steps; j++) {
				uint32_t eipsave			= emu_cpu_eip_get(emu_cpu_get(e));
				struct emu_env_w32_dll_export *dllhook	= NULL;
				ret					= 0;
				eipsave					= emu_cpu_eip_get(emu_cpu_get(e));
				dllhook					= emu_env_w32_eip_check(env);

				if (dllhook == NULL) {
					ret = emu_cpu_parse(emu_cpu_get(e));

					if (ret != -1) {
						track = emu_track_instruction_check(e, et);
						if (track == -1) {
							logmsg(LOG_WARN, 1, "CPU emulation warning - Uninitialized variable during instruction tracking.\n");
							break;
						}
					}

					if (ret != -1) ret = emu_cpu_step(emu_cpu_get(e));

					if (ret == -1) {
						logmsg(LOG_ERR, 1, "CPU emulation error - %s\n", emu_strerror(e));
						break;
					}
				}
			}
			logmsg(LOG_DEBUG, 1, "CPU emulation - Stepcount is %i.\n",j);
		}
	}
	if (found_good_candidate_after_getpc == true) logmsg(LOG_INFO, 1, "CPU emulation - Shellcode start position found.\n");
	emu_free(e);
	return(0);
}
