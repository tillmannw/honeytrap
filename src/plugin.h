/* plugin.h
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

#ifndef __HONEYTRAP_PLUGIN_H
#define __HONEYTRAP_PLUGIN_H 1

typedef struct plugin_struct {
	void *handle;
	char *name;
	char *version;
	char *filename;
	struct plugin_struct *next;
} Plugin;


char *plugin_error_str;

Plugin *plugin_list;

int load_plugin(const char *dir, const char *plugname);
int config_plugin(char *plugin_name);
void init_plugins(void);
void unload_plugins(void);
void unload_on_err(Plugin *plugin);

#endif
