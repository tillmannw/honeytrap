/* plughook.h
 * Copyright (C) 2006 Tillmann Werner <tillmann.werner@gmx.de>
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

typedef struct plugin_func_list {
	int (*func)(void *arg[]);
	char *plugnam;
	char *funcnam;
	struct plugin_func_list *next;
} PlugFuncList;


PlugFuncList *pluginlist_unload_plugins;
PlugFuncList *pluginlist_process_attack;


PlugFuncList *add_attack_func_to_list(const char *plugname, const char *funcname, int (*func)(struct s_attack));
void plughook_process_attack(struct s_attack attack);

PlugFuncList *add_unload_func_to_list(const char *plugname, const char *funcname, void (*func)(void));
void plughook_unload_plugins(void);

void init_plugin_hooks(void);
void unhook(PlugFuncList **hook_func_list, const char *plugname, const char *funcname);

#endif
