/* htm_cpuEmu.h
 * Copyright (C) 2007 Tillmann Werner <tillmann.werner@gmx.de>
 *
 * This file is free software; as a special exception the author gives
 * unlimited permission to copy and/or distribute it, with or without
 * modifications, as long as this notice is preserved.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
 * implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */

#ifndef __HT_MODULE_CPUEMU_H
#define __HT_MODULE_CPUEMU_H 1

#if HAVE_CONFIG_H
# include <config.h>
#endif

const char module_name[]="htm_cpuEmu";
const char module_version[]="0.1";


#define CODE_OFFSET 0x417001


static struct run_time_options {
	int		verbose;
	int		nasm_force;
	uint32_t	steps;
	int		testnumber;
	int		getpc;
	char		*graphfile;
} opts;

struct instr_test {
        const char	*instr;
        char		*code;
        uint16_t	codesize;
	struct {
		uint32_t	reg[8];
		uint32_t	mem_state[2];
		uint32_t	eflags;
	} in_state;
	struct {
		uint32_t	reg[8];
		uint32_t	mem_state[2];
		uint32_t	eflags;
		uint32_t	eip;
	} out_state;
};

void plugin_init(void);
void plugin_unload(void);
void plugin_register_hooks(void);
int find_shellcode(Attack *attack);

#endif
