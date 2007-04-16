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
	funclist_unload_plugins		= NULL;
	funclist_attack_preproc		= NULL;
	funclist_attack_analyze		= NULL;
	funclist_attack_savedata	= NULL;
	funclist_attack_postproc	= NULL;
	return;
}


PlugFuncList *add_attack_func_to_list(const func_prio priority, const char *plugname, const char *funcname, int (*func)(Attack)) {
	PlugFuncList *func_tmp, *func_new;

	func_tmp	= NULL;
	func_new	= NULL;

	DEBUG_FPRINTF(stdout, "    Hooking %s::%s() to 'process_attack' (priority: %d).\n", plugname, funcname, priority);
	if ((func_new = (PlugFuncList *) malloc(sizeof(PlugFuncList))) == NULL) {
		logmsg(LOG_ERR, 1, "    Error - Unable to allocate memory: %s\n", strerror(errno));
		return(NULL);
	}
	func_new->next = NULL;

	/* attach new function to list */
	switch (priority) {
	case PPRIO_PREPROC:
		func_tmp	= funclist_attack_preproc;
		break;
	case PPRIO_ANALYZE:
		func_tmp	= funclist_attack_analyze;
		break;
	case PPRIO_SAVEDATA:
		func_tmp	= funclist_attack_savedata;
		break;
	case PPRIO_POSTPROC:
		func_tmp	= funclist_attack_postproc;
		break;
	default:
		fprintf(stderr, "    Error - Unknown plugin priority.\n");
		return(NULL);
	}
	if (func_tmp) {
		while(func_tmp->next) func_tmp = func_tmp->next;
		func_tmp->next = func_new;
	} else switch (priority) {
	case PPRIO_PREPROC:
		funclist_attack_preproc	= func_new;
		break;
	case PPRIO_ANALYZE:
		funclist_attack_analyze = func_new;
		break;
	case PPRIO_SAVEDATA:
		funclist_attack_savedata = func_new;
		break;
	case PPRIO_POSTPROC:
		funclist_attack_postproc = func_new;
		break;
	default:
		fprintf(stderr, "    Error - Unknown plugin priority.\n");
		return(NULL);
	}

	func_new->func		= (void *)func;
	func_new->plugnam	= (char *)plugname;
	func_new->funcnam	= (char *)funcname;

	DEBUG_FPRINTF(stdout, "    %s::%s() hooked to 'process_attack' (priority: %d).\n", func_new->plugnam, func_new->funcnam, priority);
	return(func_new);
}


void plughook_process_attack(PlugFuncList *func_list, Attack attack) {
	PlugFuncList *func_tmp = NULL;

	logmsg(LOG_DEBUG, 1, "Calling plugins for hook 'process_attack'.\n");

	if (func_list == NULL) {
		logmsg(LOG_DEBUG, 1, "No plugins registered for hook 'process_attack'.\n");
		return;
	}

	func_tmp = func_list;
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
	func_tmp = funclist_unload_plugins;
	if (func_tmp) {
		while(func_tmp->next) func_tmp = func_tmp->next;
		func_tmp->next = func_new;
	} else funclist_unload_plugins = func_new;

	func_new->func		= (void *)func;
	func_new->plugnam	= (char *)plugname;
	func_new->funcnam	= (char *)funcname;

	DEBUG_FPRINTF(stdout, "    %s::%s() hooked to 'unload_plugins'.\n", func_new->plugnam, func_new->funcnam);
	return(func_new);
}


void plughook_unload_plugins(void) {
	PlugFuncList *func_del, *func_tmp = NULL;

	logmsg(LOG_DEBUG, 1, "Calling plugins for hook 'unload_plugins'.\n");

/*
	if (funclist_process_attack == NULL) {
		logmsg(LOG_DEBUG, 1, "No plugins registered for hook 'unload_plugins'.\n");
		return;
	}
*/

	func_tmp = funclist_unload_plugins;
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


void unhook(const func_prio priority, const char *plugname, const char *funcname) {
	switch (priority) {
	case PPRIO_PREPROC:
		unhook_from_list(&funclist_attack_preproc, plugname, funcname);
		break;
	case PPRIO_ANALYZE:
		unhook_from_list(&funclist_attack_analyze, plugname, funcname);
		break;
	case PPRIO_SAVEDATA:
		unhook_from_list(&funclist_attack_savedata, plugname, funcname);
		break;
	case PPRIO_POSTPROC:
		unhook_from_list(&funclist_attack_postproc, plugname, funcname);
		break;
	default:
		logmsg(LOG_ERR, 1, "Error - Unable to unhook %s::%s: Unsupported priority.\n", plugname, funcname);
		return;
	}
	return;
}


void unhook_from_list(PlugFuncList **hook_func_list, const char *plugname, const char *funcname) {
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
