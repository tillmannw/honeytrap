/* plughook.c
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

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "honeytrap.h"
#include "plugin.h"
#include "logging.h"
#include "plughook.h"
#include "conftree.h"


void init_plugin_hooks(void) {
	funclist_unload_plugins		= NULL;
	funclist_attack_perread		= NULL;
	funclist_attack_preproc		= NULL;
	funclist_attack_analyze		= NULL;
	funclist_attack_savedata	= NULL;
	funclist_attack_postproc	= NULL;
	return;
}


conf_node *register_plugin_confopts(const char *plugname, const char **keywords, int num) {
	int	i;
	char	full_name[264], *confopt;
	conf_node *subtree, *new;

	subtree = NULL;

	/* assemble plugin config key */
	memset(full_name, 0, 264);
	strncpy(full_name, "plugin-", 7);
	strncpy(&full_name[7], plugname, 256 < strlen(plugname) ? 256 : strlen(plugname));

	if (add_keyword(&config_keywords_tree, full_name, NULL, 0) == NULL) {
		fprintf(stderr, "  Error - Unable to add configuration keyword to tree.\n");
		exit(EXIT_FAILURE);
	}	

	DEBUG_FPRINTF(stdout, "    Plugin %s: Registering configuration keywords.\n", plugname);
	/* build tree of allowed configuration keywords */
	for (i=0; i<num; i++) {

		/* assemble full config option path */
		if ((confopt = malloc(strlen(full_name)+strlen(keywords[i])+2)) == NULL) {
			fprintf(stderr, "  Error - Unable to allocate memory: %m.\n");
			exit(EXIT_FAILURE);
		}
		memset(confopt, 0, strlen(plugname)+strlen(keywords[i])+2);
		strcat(confopt, plugname);
		strcat(confopt, ".");
		strcat(confopt, keywords[i]);

		/* add config option to tree */
		if ((new = add_keyword(&config_keywords_tree, confopt, NULL, 0)) == NULL) {
			fprintf(stderr, "  Error - Unable to add configuration keyword to tree.\n");
			exit(EXIT_FAILURE);
		}	
		free(confopt);

		if (!subtree) subtree = new;
	}
	return subtree;
}


PlugFuncList *add_attack_func_to_list(const func_prio priority, const char *plugname, const char *funcname, int (*func)(Attack)) {
	PlugFuncList *func_tmp, *func_new;

	func_tmp	= NULL;
	func_new	= NULL;

	logmsg(LOG_DEBUG, 1, "    Hooking %s::%s() to 'process_attack' (priority: %d).\n", plugname, funcname, priority);
	if ((func_new = (PlugFuncList *) malloc(sizeof(PlugFuncList))) == NULL) {
		logmsg(LOG_ERR, 1, "    Error - Unable to allocate memory: %m.\n");
		return(NULL);
	}
	func_new->next = NULL;

	/* attach new function to list */
	switch (priority) {
	case PPRIO_DYNSRV:
		func_tmp	= funclist_attack_dynsrv;
		break;
	case PPRIO_PERREAD:
		func_tmp	= funclist_attack_perread;
		break;
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
	case PPRIO_DYNSRV:
		funclist_attack_dynsrv	= func_new;
		break;
	case PPRIO_PERREAD:
		funclist_attack_perread	= func_new;
		break;
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

	logmsg(LOG_DEBUG, 1, "    %s::%s() hooked to 'process_attack' (priority: %d).\n", func_new->plugnam, func_new->funcnam, priority);
	return(func_new);
}


void plughook_process_attack(PlugFuncList *func_list, Attack *attack) {
	PlugFuncList *current_plugfunc = func_list;

	while(current_plugfunc) {
		if (current_plugfunc->func) {
			logmsg(LOG_DEBUG, 1, "Calling %s::%s().\n", current_plugfunc->plugnam, current_plugfunc->funcnam);
			current_plugfunc->func((void *)attack);
		} else logmsg(LOG_ERR, 1, "Error - Function %s::%s is not registered.\n",
			current_plugfunc->plugnam, current_plugfunc->funcnam);

		current_plugfunc = current_plugfunc->next;
	}
	current_plugfunc = NULL;
	return;
}


PlugFuncList *add_init_func_to_list(const char *plugname, const char *funcname, void (*func)(void)) {
	PlugFuncList *func_tmp, *func_new;

	DEBUG_FPRINTF(stdout, "    Hooking plugin %s to 'init_plugins'.\n", plugname);
	if ((func_new = (PlugFuncList *) malloc(sizeof(PlugFuncList))) == NULL) {
		logmsg(LOG_ERR, 1, "    Error - Unable to allocate memory: %m.\n");
		return(NULL);
	}
	func_new->next = NULL;

	/* attach new function to list */
	func_tmp = funclist_init_plugins;
	if (func_tmp) {
		while(func_tmp->next) func_tmp = func_tmp->next;
		func_tmp->next = func_new;
	} else funclist_init_plugins = func_new;

	func_new->func		= (void *)func;
	func_new->plugnam	= (char *)plugname;
	func_new->funcnam	= (char *)funcname;

	DEBUG_FPRINTF(stdout, "    %s::%s() hooked to 'init_plugins'.\n", func_new->plugnam, func_new->funcnam);
	return(func_new);
}


void plughook_init_plugins(void) {
	PlugFuncList *func_del, *func_tmp = NULL;

	func_tmp = funclist_init_plugins;
	while(func_tmp) {
		if (func_tmp->func) {
			logmsg(LOG_DEBUG, 1, "  Calling %s::%s().\n", func_tmp->plugnam, func_tmp->funcnam);
			func_tmp->func(NULL);
		} else logmsg(LOG_DEBUG, 1, "  Error - Function %s::%s is not registered.\n",
			func_tmp->plugnam, func_tmp->funcnam);
		func_del = func_tmp;
		func_tmp = func_tmp->next;
		logmsg(LOG_DEBUG, 1, "  Unhooking %s::%s().\n", func_del->plugnam, func_del->funcnam);
		free(func_del);
	}
	return;
}


PlugFuncList *add_unload_func_to_list(const char *plugname, const char *funcname, void (*func)(void)) {
	PlugFuncList *func_tmp, *func_new;

	DEBUG_FPRINTF(stdout, "    Hooking plugin %s to 'unload_plugins'.\n", plugname);
	if ((func_new = (PlugFuncList *) malloc(sizeof(PlugFuncList))) == NULL) {
		logmsg(LOG_ERR, 1, "    Error - Unable to allocate memory: %m.\n");
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

	func_tmp = funclist_unload_plugins;
	while(func_tmp) {
		if (func_tmp->func) {
			logmsg(LOG_DEBUG, 1, "Calling %s::%s().\n", func_tmp->plugnam, func_tmp->funcnam);
			func_tmp->func(NULL);
		} else logmsg(LOG_ERR, 1, "Error - Function %s::%s is not registered.\n",
			func_tmp->plugnam, func_tmp->funcnam);
		func_del = func_tmp;
		func_tmp = func_tmp->next;
		logmsg(LOG_DEBUG, 1, "Unhooking %s::%s().\n", func_del->plugnam, func_del->funcnam);
		free(func_del);
	}
	return;
}


void unhook(const func_prio priority, const char *plugname, const char *funcname) {
	switch (priority) {
	case PPRIO_DYNSRV:
		unhook_from_list(&funclist_attack_dynsrv, plugname, funcname);
		break;
	case PPRIO_PERREAD:
		unhook_from_list(&funclist_attack_perread, plugname, funcname);
		break;
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
