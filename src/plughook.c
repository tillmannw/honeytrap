/* plughook.c
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

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "honeytrap.h"
#include "plugin.h"
#include "logging.h"
#include "plughook.h"


void init_plugin_hooks(void) {
	pluginlist_unload_plugins	= NULL;
	pluginlist_process_attack	= NULL;
	return;
}


PlugFuncList *add_attack_func_to_list(const char *plugname, const char *funcname, int (*func)(struct s_attack)) {
	PlugFuncList *func_tmp, *func_new;

	DEBUG_FPRINTF(stdout, "    Hooking plugin %s to 'process_attack'.\n", plugname);
	if ((func_new = (PlugFuncList *) malloc(sizeof(PlugFuncList))) == NULL) {
		logmsg(LOG_ERR, 1, "    Error - Unable to allocate memory: %s\n", strerror(errno));
		return(NULL);
	}
	func_new->next = NULL;

	/* attach new function to list */
	func_tmp = pluginlist_process_attack;
	if (func_tmp) {
		while(func_tmp->next) func_tmp = func_tmp->next;
		func_tmp->next = func_new;
	} else pluginlist_process_attack = func_new;

	func_new->func		= (void *)func;
	func_new->plugnam	= (char *)plugname;
	func_new->funcnam	= (char *)funcname;

	DEBUG_FPRINTF(stdout, "    %s::%s() hooked to 'process_attack'.\n", func_new->plugnam, func_new->funcnam);
	return(func_new);
}


void plughook_process_attack(struct s_attack attack) {
	PlugFuncList *func_tmp = NULL;

	logmsg(LOG_DEBUG, 1, "Calling plugins for hook 'process_attack'.\n");

	if (pluginlist_process_attack == NULL) {
		logmsg(LOG_DEBUG, 1, "No plugins registered for hook 'process_attack'.\n");
		return;
	}

	func_tmp = pluginlist_process_attack;
	while(func_tmp) {
		if (func_tmp->func) {
			logmsg(LOG_DEBUG, 1, "Calling %s::%s().\n", func_tmp->plugnam, func_tmp->funcnam);
			func_tmp->func((void *)&attack);
		} else logmsg(LOG_ERR, 1, "Error - Function %s::%s is not registered.\n",
			func_tmp->plugnam, func_tmp->funcnam);
		func_tmp = func_tmp->next;
	}
	return;
}


PlugFuncList *add_unload_func_to_list(const char *plugname, const char *funcname, void (*func)(void)) {
	PlugFuncList *func_tmp, *func_new;

	DEBUG_FPRINTF(stdout, "    Hooking plugin %s to 'unload_plugins'.\n", plugname);
	if ((func_new = (PlugFuncList *) malloc(sizeof(PlugFuncList))) == NULL) {
		logmsg(LOG_ERR, 1, "    Error - Unable to allocate memory: %s\n", strerror(errno));
		return(NULL);
	}
	func_new->next = NULL;

	/* attach new function to list */
	func_tmp = pluginlist_unload_plugins;
	if (func_tmp) {
		while(func_tmp->next) func_tmp = func_tmp->next;
		func_tmp->next = func_new;
	} else pluginlist_unload_plugins = func_new;

	func_new->func		= (void *)func;
	func_new->plugnam	= (char *)plugname;
	func_new->funcnam	= (char *)funcname;

	DEBUG_FPRINTF(stdout, "    %s::%s() hooked to 'unload_plugins'.\n", func_new->plugnam, func_new->funcnam);
	return(func_new);
}


void plughook_unload_plugins(void) {
	PlugFuncList *func_del, *func_tmp = NULL;

	logmsg(LOG_DEBUG, 1, "Calling plugins for hook 'unload_plugins'.\n");

	if (pluginlist_process_attack == NULL) {
		logmsg(LOG_DEBUG, 1, "No plugins registered for hook 'unload_plugins'.\n");
		return;
	}

	func_tmp = pluginlist_unload_plugins;
	while(func_tmp) {
		if (func_tmp->func) {
			logmsg(LOG_DEBUG, 1, "Calling %s::%s().\n", func_tmp->plugnam, func_tmp->funcnam);
			func_tmp->func(NULL);
		} else logmsg(LOG_ERR, 1, "Error - Function %s::%s is not registered.\n",
			func_tmp->plugnam, func_tmp->funcnam);
		func_del = func_tmp;
		func_tmp = func_tmp->next;
		logmsg(LOG_DEBUG, 1, "Unhooking %s::plugin_unload().\n", func_del->plugnam);
		free(func_del);
	}
	return;
}


void unhook(PlugFuncList **hook_func_list, const char *plugname, const char *funcname) {
	PlugFuncList *func_tmp, *func_del, *func_before_del;

	/* search module name in hook list */ 
	func_del = NULL;
	func_tmp = *hook_func_list;
	func_before_del = *hook_func_list;
	while(func_tmp) {
		if ((strcmp(func_tmp->plugnam, plugname) == 0) && (strcmp(func_tmp->funcnam, funcname) == 0)) {
			func_del = func_tmp;
			break;
		}
		func_before_del = func_tmp;
		func_tmp = func_tmp->next;
	}
	if (func_del) {
		/* hook found, delete it from list */
		if (func_del == *hook_func_list) *hook_func_list = (*hook_func_list)->next;
		else func_before_del->next = func_del->next;

		/* free struct */
		logmsg(LOG_DEBUG, 1, "Unhooking %s::%s().\n", plugname, funcname);
		free(func_del);
	} else {
		/* hook not found */
		logmsg(LOG_WARN, 1, "Unable to unhook %s::%s(): Function not registered.\n", plugname, funcname);
	}
	return;
}
