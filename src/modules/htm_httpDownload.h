/* htm_httpDownload.h
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

#ifndef __HT_MODULE_HTTPDOWNLOAD_H
#define __HT_MODULE_HTTPDOWNLOAD_H 1

#if HAVE_CONFIG_H
# include <config.h>
#endif

void plugin_init(void);
void plugin_unload(void);
void plugin_register_hooks(void);
void plugin_register_confopts(void);
conf_node *plugin_process_confopts(conf_node *tree, conf_node *node, void *opt_data);
int cmd_parse_for_http_url(Attack *attack);

#endif
