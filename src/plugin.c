/* plugin.c
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
#include <dlfcn.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <dirent.h>
#include <fnmatch.h>
#include <stdlib.h>

#include "honeytrap.h"
#include "plugin.h"
#include "plughook.h"
#include "logging.h"


int load_plugin(const char *dir, const char* plugname) {
	struct stat statbuf;
	struct dirent **namelist;
	int n, ret;
	char *full_path, full_name[264];
	DIR *plugindir;

	ret		= 0;
	full_path	= NULL;
	plugin_list	= NULL;

	if (strlen(plugname) > 265) {
		fprintf(stderr, "  Error - Plugin name exceeds maximum length of 256 charakters: %s\n", plugname);
		return(-1);
	}

	/* plugin directory must be configured */
	if (!dir) {
		fprintf(stderr, "  Error - Plugin directory not set while trying to load plugin %s.\n", plugname);
		exit(EXIT_FAILURE);
	}

	if ((plugindir = opendir(dir)) == NULL) {
		fprintf(stderr, "  Error - Unable to open plugin directory: %m.\n");
		exit(EXIT_FAILURE);
	}
	
	DEBUG_FPRINTF(stdout, "  Looking for plugin %s in %s\n", plugname, dir);
	if ((n = scandir(dir, &namelist, 0, alphasort)) < 0) {
		fprintf(stderr, "  Error - Unable to scan plugin directory: %m.\n");
		return(-1);
	} else while(n--) {
		stat(namelist[n]->d_name, &statbuf);

		/* assemble full name */
		memset(full_name, 0, 264);
		strncpy(full_name, "htm_", 4);
		strncpy(&full_name[4], plugname, strlen(plugname));
		strncpy(&full_name[4+strlen(plugname)], ".so", 3);

		if ((ret = fnmatch(full_name, namelist[n]->d_name, 0)) == 0) {
			/* found the plugin */
			if ((full_path = (char *) malloc(strlen(dir) + strlen(namelist[n]->d_name) + 2)) == NULL) {
				perror("  Error - Unable to allocate memory");
				exit(EXIT_FAILURE);
			}
			snprintf(full_path, strlen(dir)+strlen(namelist[n]->d_name)+2, "%s/%s", dir, namelist[n]->d_name);
			DEBUG_FPRINTF(stdout, "  Plugin found: %s\n", full_path);
			config_plugin(full_path);
			free(full_path);
			free(namelist[n]);
			break;
		}
		free(namelist[n]);
	}
	closedir(plugindir);
	if (ret != 0) {
		fprintf(stderr, "  Error - Unable to load plugin %s: %m.\n", full_name);
		exit(EXIT_FAILURE);
	}
	free(namelist);
	
	return(1);
}

int config_plugin(char *plugin_name) {
	int (*plugin_config)();
	void (*plugin_init)();
	void (*plugin_unload)();
	Plugin *last_plugin, *new_plugin;

	/* allocate memory for new plugin and attach it to the plugin list */
	if ((new_plugin = (Plugin *) malloc(sizeof(Plugin))) == NULL) {
		fprintf(stderr, "    Error - Unable to allocate memory: %m.\n");
		return(-1);
	} else {
		new_plugin->handle = NULL;
		new_plugin->name = NULL;
		new_plugin->version = NULL;
		new_plugin->next = NULL;
		new_plugin->filename = NULL;
	}

	if (plugin_name == NULL) {
		fprintf(stderr, "  Error loading plugin - No name given.\n");
		return(-1);
	} else { 
		if ((new_plugin->handle = (void *) malloc(sizeof(int))) == NULL) { 
			fprintf(stderr, "  Error loading plugin - Unable to allocate memory: %m.\n");
			free(new_plugin);
			return(-1);
		} else new_plugin->filename = (char *) strdup(plugin_name);
	}

	dlerror();      /* Clear any existing error */
	if (((new_plugin->handle = dlopen(new_plugin->filename, RTLD_NOW)) == NULL) &&
	    ((plugin_error_str = (char *) dlerror()) != NULL)) {
		fprintf(stderr, "  Unable to initialize plugin: %s\n", plugin_error_str);
		unload_on_err(new_plugin);
		exit(EXIT_FAILURE);
	}

	/* determin internal module name and version string */
	if (((new_plugin->name = (char *) dlsym(new_plugin->handle, "module_name")) == NULL) &&
	    ((plugin_error_str = (char *) dlerror()) != NULL)) {
		/* handle error, the symbol wasn't found */
		fprintf(stderr, "  Unable to initialize plugin: %s\n", plugin_error_str);
		fprintf(stderr, "  %s seems not to be a honeytrap plugin.\n", new_plugin->filename);
		unload_on_err(new_plugin);
		return(-1);
	}
	if (((new_plugin->version = (char *) dlsym(new_plugin->handle, "module_version")) == NULL) &&
	    ((plugin_error_str = (char *) dlerror()) != NULL)) {
		/* handle error, the symbol wasn't found */
		fprintf(stderr, "  Unable to initialize plugin %s: %s\n", new_plugin->name, plugin_error_str);
		fprintf(stderr, "  %s seems not to be a honeytrap plugin.\n", new_plugin->filename);
		unload_on_err(new_plugin);
		return(-1);
	}
	fprintf(stdout, "  Loading plugin %s v%s\n", new_plugin->name, new_plugin->version);

	DEBUG_FPRINTF(stdout, "  Configuring plugin %s.\n", new_plugin->name);
	/* resolve module's unload function and add it to unload hook */
	if (((plugin_unload = dlsym(new_plugin->handle, "plugin_unload")) == NULL) && 
	    ((plugin_error_str = (char *) dlerror()) != NULL)) {
		/* handle error, the symbol wasn't found */
		fprintf(stderr, "    Unable to initialize plugin %s: %s\n", new_plugin->name, plugin_error_str);
		fprintf(stderr, "    %s seems not to be a honeytrap plugin.\n", new_plugin->filename);
		unload_on_err(new_plugin);
		return(-1);
	}
	if (!add_unload_func_to_list(new_plugin->name, "plugin_unload", plugin_unload)) {
		fprintf(stderr, "    Unable to register module for hook 'unload_plugins': %s\n", plugin_error_str);
		unload_on_err(new_plugin);
		return(-1);
	}

	/* resolve and call module's config function */
	if (((plugin_config = dlsym(new_plugin->handle, "plugin_config")) == NULL) && 
	    ((plugin_error_str = (char *) dlerror()) != NULL)) {
		/* handle error, the symbol wasn't found */
		fprintf(stderr, "\n    Unable to resolve symbol 'plugin_config': %s\n", plugin_error_str);
		return(-1);
	}
	plugin_config();

	// resolve module's init function and add it to init hook 
	if (((plugin_init = dlsym(new_plugin->handle, "plugin_init")) == NULL) && 
	    ((plugin_error_str = (char *) dlerror()) != NULL)) {
		/* handle error, the symbol wasn't found */
		fprintf(stderr, "    Unable to initialize plugin %s: %s\n", new_plugin->name, plugin_error_str);
		fprintf(stderr, "    %s seems not to be a honeytrap plugin.\n", new_plugin->filename);
		unload_on_err(new_plugin);
		return(-1);
	}
	if (!add_init_func_to_list(new_plugin->name, "plugin_init", plugin_init)) {
		fprintf(stderr, "    Unable to register module for hook 'init_plugins': %s\n", plugin_error_str);
		unload_on_err(new_plugin);
		return(-1);
	}

	/* attach plugin to plugin_list */
	if (!plugin_list) plugin_list = new_plugin;
	else {
		last_plugin = plugin_list;
		while(last_plugin->next) last_plugin = last_plugin->next;
		last_plugin->next = new_plugin;
	}
	
	return(1);
}


void init_plugins(void) {
	/* call init functions from plugins */
	logmsg(LOG_NOTICE, 1, "Initializing plugins.\n");
	plughook_init_plugins();
	
	return;
}


void unload_plugins(void) {
	Plugin *cur_plugin;
	
	/* call unload functions from plugins */
	logmsg(LOG_DEBUG, 1, "Calling plugin callbacks for hook 'unload_plugins'.\n");
	plughook_unload_plugins();
	
	/* unload plugin and free mem for filename and plugin 
	 * other variables in struct are symbols and do not need to be freed */
	while(plugin_list) {
		cur_plugin = plugin_list->next;
		if (dlclose(plugin_list->handle) != 0)
			logmsg(LOG_ERR, 1, "Error - Unable to unload plugin %s.\n", plugin_list->name);
		free(plugin_list->filename);
		free(plugin_list);
		plugin_list = cur_plugin;
	}
	return;
}


void unload_on_err(Plugin *plugin) {
	fprintf(stderr, "  Unloading plugin on initialization error.\n");
	if (plugin) {
		if (plugin->handle) dlclose(plugin->handle);
		free(plugin->filename);
	}
	free(plugin);
	return;
}
