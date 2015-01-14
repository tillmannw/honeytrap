/* plughook.h
 * Copyright (C) 2006-2007 Tillmann Werner <tillmann.werner@gmx.de>
 *
 * This file is free software; as a special exception the author gives
 * unlimited permission to copy and/or distribute it, with or without
 * modifications, as long as this notice is preserved.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
 * implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */

#ifndef __HONEYTRAP_PLUGHOOK_H
#define __HONEYTRAP_PLUGHOOK_H 1

#include "attack.h"
#include "conftree.h"
#include "plugin.h"

typedef enum {
	PPRIO_DYNSRV	= 0,	// functions of this prio get invoked before a dynamic server binds to a port
	PPRIO_PERREAD	= 1,	// for plugin functions that shall get called for every read on an attack connection
	PPRIO_PREPROC	= 2,	// attack preprocessing, e.g., decryption
	PPRIO_ANALYZE	= 3,	// attack analysis, e.g., ftp command parsing
	PPRIO_SAVEDATA	= 4,	// for data-saving plugins
	PPRIO_POSTPROC	= 5,	// attack postprocessing, e.g., IDS signature generation or other time complex tasks
} func_prio;

typedef struct plugin_func_list {
	int (*func)(void *arg[]);
	func_prio prio;
	char *plugnam;
	char *funcnam;
	struct plugin_func_list *next;
} PlugFuncList;

PlugFuncList *funclist_init_plugins;
PlugFuncList *funclist_unload_plugins;
PlugFuncList *funclist_attack_dynsrv;
PlugFuncList *funclist_attack_perread;
PlugFuncList *funclist_attack_preproc;
PlugFuncList *funclist_attack_analyze;
PlugFuncList *funclist_attack_savedata;
PlugFuncList *funclist_attack_postproc;

PlugFuncList *add_attack_func_to_list(const func_prio priority, const char *plugname, const char *funcname, int (*func)(struct s_attack));
void plughook_process_attack(PlugFuncList *func_list, Attack *attack);

PlugFuncList *add_init_func_to_list(const char *plugname, const char *funcname, void (*func)(void));
void plughook_init_plugins(void);

PlugFuncList *add_unload_func_to_list(const char *plugname, const char *funcname, void (*func)(void));
void plughook_unload_plugins(void);

void init_plugin_hooks(void);
conf_node *register_plugin_confopts(const char *plugname, const char **keywords, int num);
void unhook(const func_prio priority, const char *plugname, const char *funcname);
void unhook_from_list(PlugFuncList **hook_func_list, const char *plugname, const char *funcname);

#endif
