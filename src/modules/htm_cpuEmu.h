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
const char module_version[]="1.0.1";

static const char *config_keywords[] = {
	"execute_shellcode",
	"createprocess_cmd"
};

int	execute_shellcode;
char	*createprocess_cmd;


#define CODE_OFFSET 0x417001


static struct run_time_options {
	int		verbose;
	int		nasm_force;
	uint32_t	steps;
	unsigned char	*scode;
	uint32_t	size;
	int		offset;

	struct {
		struct {
			char	*host;
			int	port;
		} connect, bind;
		struct {
			struct emu_hashtable *commands;
		} commands;
	} override;
} opts;


void plugin_init(void);
void plugin_unload(void);
void plugin_register_hooks(void);
int find_shellcode(Attack *attack);

#endif
