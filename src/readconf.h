/* readconf.h
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

#ifndef __HONEYTRAP_READCONF_H
#define __HONEYTRAP_READCONF_H 1

#include <netdb.h>

#include "conftree.h"

char *user, *group;

typedef struct proxy_dest {
	u_int16_t	protocol;
	u_int16_t	port;
	char		*host;
} proxy_dest;

typedef struct portcfg {
	u_char		mode;
	u_char		*response;
	proxy_dest	*target;
	u_int16_t	port;
	u_int16_t	protocol;
} portcfg;

struct protomap {
	u_char		protocol;
	struct protomap	*next;
};
struct portmap {
	u_int16_t	port;
	struct portmap	*next;
};
struct pconfmap {
	struct portmap	*portmap;
	struct protomap	*protomap;
	proxy_dest	*target;
	struct pconfmap	*next;
};

portcfg *port_flags_tcp[0xffff];	// explicit port configuration for each tcp port
portcfg *port_flags_udp[0xffff];	// explicit port configuration for each udp port

#define OPT_IS(A)	(strcmp(node->keyword, (A)) == 0)
#define OPT_SET(A, B)	{ free(B); B = value; if (B) DEBUG_FPRINTF(stdout, A, B); }


typedef conf_node *(*process_confopt_fn)(conf_node *tree, conf_node *node, void *opt_data);


void *get_value(char *buf, const char delim);
int configure(int argc, char *argv[]);
conf_node *process_conftree(conf_node *conftree, conf_node *tree, process_confopt_fn proc_opt, void *opt_data);
conf_node *process_confopt			(conf_node *tree, conf_node *node, void *opt_data);
conf_node *process_confopt_portconf		(conf_node *tree, conf_node *node, void *opt_data);
conf_node *process_confopt_portconf_simple	(conf_node *tree, conf_node *node, void *mode);
conf_node *process_confopt_portconf_proxy	(conf_node *tree, conf_node *node, void *pmap);
conf_node *process_confopt_portconf_proxy_map	(conf_node *tree, conf_node *node, void *opt_data);
conf_node *process_confopt_plugin		(conf_node *tree, conf_node *node, void *opt_data);
enum lcfg_status print_config(const char *key, void *data, size_t len, void *user_data);

#endif
