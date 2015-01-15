/* readconf.c
 * Copyright (C) 2006-2009 Tillmann Werner <tillmann.werner@gmx.de>
 *
 * This file is free software; as a special exception the author gives
 * unlimited permission to copy and/or distribute it, with or without
 * modifications, as long as this notice is preserved.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
 * implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */

#include <errno.h>
#include <stdio.h>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <netdb.h>
#include <strings.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/file.h>

#include "readconf.h"
#include "parseconf.h"
#include "conftree.h"
#include "honeytrap.h"
#include "logging.h"
#include "response.h"
#include "util.h"
#include "ctrl.h"
#include "signals.h"
#include "plugin.h"
#include "plughook.h"
#include "tcpip.h"
#include "pcapmon.h"
#include "ipqmon.h"

#ifdef USE_PCAP_MON
  #define OPTSTRING	"vh?pDmL:P:C:i:a:l:r:u:g:t:"
#else
  #define OPTSTRING	"vh?pDmL:P:C:l:r:u:g:t:"
#endif

/* allowed configuration keywords
 * use dots separate hierarchy levels */
static const char *config_keywords[] = {
	"logfile",
	"pidfile",
	"response_dir",
	"plugin_dir",
	"read_limit",
	"bind_address",
	"replace_private_ips",
#ifdef USE_PCAP_MON
	"promisc",
#endif
	"user",
	"group",
	"include",
	"portconf_default",
	"portconf",
	"portconf.ignore.protocol",
	"portconf.ignore.port",
	"portconf.normal.protocol",
	"portconf.normal.port",
	"portconf.proxy",
	"portconf.proxy.map.protocol",
	"portconf.proxy.map.port",
	"portconf.proxy.map.target_host",
	"portconf.proxy.map.target_protocol",
	"portconf.proxy.map.target_port",
	"portconf.mirror.protocol",
	"portconf.mirror.port"
};

/* global config tree */
struct lcfg *confkeys_tree;


conf_node *process_conftree(conf_node *conftree, conf_node *tree, process_confopt_fn proc_opt, void *opt_data) {
	conf_node	*cur_node = NULL;

	if (!tree) return(NULL);

	cur_node = tree;
	while (cur_node) {
		if (proc_opt(tree, cur_node, opt_data) == NULL) return(NULL);
		if (cur_node->first_leaf) {
			// descend to subtree
			if ((cur_node = process_conftree(tree, cur_node->first_leaf, proc_opt, NULL)) == NULL) {
				fprintf(stderr, "  Error - Subtree processing failed.\n");
				return(NULL);
			} else return(cur_node);

			if (cur_node->next) cur_node = cur_node->next;
			else return(cur_node);
		}
		if (cur_node->next) cur_node = cur_node->next;
		else return(cur_node);
	}

	return(cur_node);
}


enum lcfg_status check_conffile(const char *key, void *data, size_t len, void *tree) {
	conf_node	*new_node;

	new_node	= NULL;

	if ((new_node = add_keyword(&config_tree, key, data, len)) == NULL) {
		fprintf(stderr, "Error - Unable to add configuration option to tree.\n");
		return(lcfg_status_error);
	}	

	return(lcfg_status_ok);
}


int configure(int my_argc, char *my_argv[]) {
#ifdef USE_PCAP_MON
	char			*bpf_cmd_ext, errbuf[PCAP_ERRBUF_SIZE];
	struct hostent		*ip_cmd_opt;
#endif
	int			option;
	struct passwd		*pwd_entry;
	struct group		*grp_entry;
	int			i;

	config_keywords_tree	= NULL;
	config_tree		= NULL;

	bind_address.s_addr 	= INADDR_ANY;

	/* build tree of allowed configuration keywords */
	for (i=0; i<sizeof(config_keywords)/sizeof(char *); i++) {
		if (add_keyword(&config_keywords_tree, config_keywords[i], NULL, 0) == NULL) {
			fprintf(stderr, "  Error - Unable to add configuration keyword to tree.\n");
			exit(EXIT_FAILURE);
		}	
	}

	/* initialilzation of variables */
	response_list		= NULL;	/* initialize default response list */
	pidfile_fd		= 0;
#ifdef USE_PCAP_MON
	bpf_cmd_ext		= NULL;	/* bpf string extension ('expression' from command line) */
	ip_cmd_opt		= NULL;	/* source ip address for bpf string */
#endif

	/* initialize port flags array with zeros */
	memset(port_flags_tcp, 0, 0xffff * sizeof(portcfg *)); 
	memset(port_flags_udp, 0, 0xffff * sizeof(portcfg *)); 

	/* initialization of plugin hooks */
	init_plugin_hooks();
	/* scan command line options to determine logging level or print version number or usage */
	while((option = getopt(my_argc, my_argv, OPTSTRING)) > 0) {
		switch(option) {
			case 't':
				if ((atoi(optarg) < 7) && (atoi(optarg) >= 0)) log_level = atoi(optarg);
				else {
					fprintf(stderr, "  Error - Log level must be a value between 0 and 6.\n");
					exit(EXIT_FAILURE);
				}
				break;
			case 'v':
				fprintf(stdout, "%s\n", PACKAGE_STRING);
				exit(EXIT_SUCCESS);
			case 'h':
			case '?':
				usage(my_argv[0]);
			default:
				break;
		}
	}

	/* initialization phase, all logging goes to stdout or stderr */
	fprintf(stdout, "\nhoneytrap v%s - Initializing.\n", VERSION);

	if (first_init) {	
		DEBUG_FPRINTF(stdout, "  Saving old working directory.\n");
		if (getcwd(old_cwd, 1024) == NULL) {
			DEBUG_FPRINTF(stderr, "  Error - Unable to determine current working directory.\n");
			exit(EXIT_FAILURE);
		}

		/* scan command line options to get config file name */
		optind = 1;
		while((option = getopt(my_argc, my_argv, OPTSTRING)) > 0) {
			switch(option) {
				case 'C':
					/* config file */
					conffile_name = strdup(optarg);
					DEBUG_FPRINTF(stdout, "  Reading configuration from %s.\n", conffile_name);
					break;
				case 'D':
					/* don't daemonize */
					daemonize = 0;
				DEBUG_FPRINTF(stdout, "  Not daemonizing - staying in foreground.\n");
					break;
				default:
					break;
			}
		}
	}
		
	/* process config file */
	if ((confkeys_tree = parse_config_file(conffile_name)) == NULL) exit(EXIT_FAILURE);
	else if (lcfg_accept(confkeys_tree, check_conffile, 0) != lcfg_status_ok) {
		/* invalid config keyword found, delete config tree */
		lcfg_delete(confkeys_tree);
		exit(EXIT_FAILURE);
	}
	if (process_conftree(config_tree, config_tree, process_confopt, NULL) == NULL) {
		fprintf(stderr, "  Error - Unable to process configuration tree.\n");
		exit(EXIT_FAILURE);
	}


	/* scan command line options to get logfile name */
	optind = 1;
	while((option = getopt(my_argc, my_argv, OPTSTRING)) > 0) {
		switch(option) {
			case 'L':
				logfile_name = strdup(optarg);
				DEBUG_FPRINTF(stdout, "  Logfile is %s.\n", logfile_name);
				break;
			default:
				break;
		}
	}


	/* initialize plugins */
//	init_plugins();


	/* install signal handlers */
	install_signal_handlers();


	/* process remaining options now */
	optind = 1;
	while((option = getopt(my_argc, my_argv, OPTSTRING)) > 0) {
		switch(option) {
#ifdef USE_PCAP_MON
			case 'i':
				dev = strdup(optarg);
				break;
			case 'a':
				if ((ip_cmd_opt = gethostbyname(optarg)) == NULL) {
					perror("  Error - Invalid hostname or ip address\n");
					exit(EXIT_FAILURE);
				}
				break;
			case 'p':
				promisc_mode = 1;
				break;
#endif
			case 'l':
				conn_timeout = strtoul(optarg, NULL, 0);
				if((conn_timeout < 0) || (conn_timeout > 255)) {
					fprintf(stderr,
						"  Error - Listen timeout must be a value between 0 and 255.\n");
					exit(EXIT_FAILURE);
				}
				break;
			case 'r':
				read_timeout = strtoul(optarg, NULL, 0);
				if((read_timeout < 0) || (read_timeout > 255)) {
					fprintf(stderr,
						"  Error - Read timeout must be a value between 0 and 255.\n");
					exit(EXIT_FAILURE);
				}
				break;
			case 'u':
				if ((pwd_entry = getpwnam(optarg)) == NULL) {
					if (errno) fprintf(stderr, "  Invalid user: %m.\n");
					else fprintf(stderr, "  User %s not found.\n", optarg);
					exit(EXIT_FAILURE);
				} else {
					u_id = pwd_entry->pw_uid;
					user = strdup(optarg);
				}
				break;
			case 'g':
				if ((grp_entry = getgrnam(optarg)) == NULL) {
					if (errno) fprintf(stderr, "  Invalid group: %m.\n");
					else fprintf(stderr, "  Group %s not found.\n", optarg);
					exit(EXIT_FAILURE);
				} else {
					g_id = grp_entry->gr_gid;
					group = strdup(optarg);
				}
				break;
			case 'P':
				/* pid file */
				free(pidfile_name);
				pidfile_name = strdup(optarg);
				DEBUG_FPRINTF(stdout, "  Pid file is %s.\n", pidfile_name);
				break;
			case 'D':
			case 'L':
			case 't':
			default:
				break;
		}
	}


#ifdef USE_PCAP_MON
	/* get IPv4 address from interface */
	if (dev == NULL) {
		DEBUG_FPRINTF(stdout, "  No device given, trying to use default device.\n");
		if ((dev = pcap_lookupdev(errbuf)) == NULL) {
			fprintf(stderr, "  Error - Unable to determine default network device: %s.\n", errbuf);
			exit(EXIT_FAILURE);
		}
		fprintf(stdout, "  Default device is %s.\n", dev);
	}
#endif

	fprintf(stdout, "  Servers will run as user %s (%d).\n", user, u_id);
	fprintf(stdout, "  Servers will run as group %s (%d).\n", group, g_id);


	/* load default responses */
	if (response_dir) {
		fprintf(stdout, "  Loading default responses.\n");
		if (load_default_responses(response_dir) == -1)
			fprintf(stdout, "  Warning - Unable to load default responses.\n");
	}

	fprintf(stdout,"  Connections will be handled in %s mode by default.\n", MODE(portconf_default));


#ifdef USE_PCAP_MON
	DEBUG_FPRINTF(stdout, "  Using %s.\n", pcap_lib_version());
	if(promisc_mode) fprintf(stdout,"  Promiscuous mode enabled.\n");

	/* assemble bpf expression from command line */
	if ((first_init ) && (optind < my_argc)) {
		while (optind < my_argc) {
			if (!bpf_cmd_ext) {
				bpf_cmd_ext = (char *) strdup(my_argv[optind]);
			} else {
				if ((bpf_cmd_ext = (char *) realloc(bpf_cmd_ext,
					strlen(bpf_cmd_ext)+strlen(my_argv[optind])+2)) == NULL) {
					perror("  Error - Unable to allocate memory");
					exit(EXIT_FAILURE);
				}
				snprintf(bpf_cmd_ext+strlen(bpf_cmd_ext), strlen(my_argv[optind])+2,
					" %s%c", my_argv[optind], 0);
			}
			optind++;
		}
		DEBUG_FPRINTF(stdout, "  Command line bpf expression is '%s'\n", bpf_cmd_ext); 
	}

	/* create berkeley packet filter string */
	if (first_init) {
		if (bpf_filter_string) {
			free(bpf_filter_string);
			bpf_filter_string = NULL;
		}
		bpf_filter_string = (char *) strdup(create_bpf(bpf_cmd_ext, ip_cmd_opt, dev));
	}
#endif


	/* open logfile */
	if((logfile_fd = open(logfile_name, EXCL_FILE_RW, 0644)) == -1) {
		fprintf(stderr, "  Error - Unable to open logfile %s: %m.\n", logfile_name);
		exit(EXIT_FAILURE);
	}
	fprintf(stdout, "  Logging to %s.\n", logfile_name);


	fprintf(stdout, "  Core module initialized.\n");
	logmsg(LOG_ERR, 0, "\nhoneytrap v%s %s\n", VERSION, COPYRIGHT_STRING);

	first_init = 0;
	return(1);
}


conf_node *process_confopt(conf_node *tree, conf_node *node, void *opt_data) {
	char		*value;
	struct passwd	*pwd_entry;
	struct group	*grp_entry;
	struct lcfg	*confkeys_subtree;
	conf_node	*confopt;


	pwd_entry		= NULL;
	grp_entry		= NULL;
	confopt			= NULL;
	value			= NULL;
	confkeys_subtree	= NULL;

	if ((confopt = check_keyword(tree, node->keyword)) == NULL) return(node);

	do {
		if (node->val) {
			if ((value = malloc(node->val->size+1)) == NULL) {
				perror("  Error - Unable to allocate memory");
				exit(EXIT_FAILURE);
			}
			memset(value, 0, node->val->size+1);
			memcpy(value, node->val->data, node->val->size);
		}

		if (OPT_IS("include")) {
			/* include line found, do recursive processing */
			DEBUG_FPRINTF(stdout, "  Including configuration from %s.\n", value);
			if ((confkeys_subtree = parse_config_file(value)) == NULL) exit(EXIT_FAILURE);
			if (lcfg_accept(confkeys_subtree, check_conffile, 0) != lcfg_status_ok) {
				/* invalid config keyword found, delete config tree */
				lcfg_delete(confkeys_subtree);
				exit(EXIT_FAILURE);
			}
		} else if (OPT_IS("portconf_default")) {
			if (strcmp(value, "ignore") == 0) portconf_default = PORTCONF_IGNORE;
			else if (strcmp(value, "normal") == 0) portconf_default = PORTCONF_NORMAL;
			else if (strcmp(value, "mirror") == 0) portconf_default = PORTCONF_MIRROR;
			else if (strcmp(value, "proxy") == 0) {
				fprintf(stderr, "  Error - Proxy mode as default port configuration is currently not supported.\n");
				exit(EXIT_FAILURE);
			} else {
				fprintf(stderr, "  Error - Unsupported default port configuration: %s .\n", value);
				exit(EXIT_FAILURE);
			}
		} else if (strstr(node->keyword, "plugin-") == node->keyword) {
			/* load plugins */
			value = strchr(node->keyword, '-') + 1;
			load_plugin(plugin_dir, value);
			process_conftree(node, node->first_leaf, process_confopt_plugin, NULL);
			node->first_leaf = NULL;
			conftree_children_free(node);
#ifdef USE_PCAP_MON
		} else if (OPT_IS("promisc")) {
			if (strcmp(value, "on") == 0) promisc_mode = 1;
			else if (strcmp(value, "off") == 0) promisc_mode = 0;
			else {
				fprintf(stderr, "  Error - Invalid value '%s' for option '%s'.\n", value, node->keyword);
				exit(EXIT_FAILURE);
			}
			DEBUG_FPRINTF(stdout, "  Setting promiscuous mode to on.\n");
#endif
		} else if (OPT_IS("replace_private_ips")) {
			if (strcmp(value, "yes") == 0) replace_private_ips = 1;
			else if (strcmp(value, "no") == 0) replace_private_ips = 0;
			else {
				fprintf(stderr, "  Error - Invalid value '%s' for option '%s'.\n", value, node->keyword);
				exit(EXIT_FAILURE);
			}
			DEBUG_FPRINTF(stdout, "  Setting promiscuous mode to on.\n");
		} else if (OPT_IS("read_limit")) {
			read_limit = atol(value);
			if (read_limit <= 0) {
				fprintf(stderr, "  Error - Read limit must be a positive value.\n");
				exit(EXIT_FAILURE);
			}
			free(value);
			DEBUG_FPRINTF(stdout, "  Setting read limit to %d.\n", read_limit);
		} else if (OPT_IS("pidfile")) OPT_SET("  Setting process id file to %s.\n", pidfile_name)
		else if (OPT_IS("logfile")) OPT_SET("  Setting logfile to %s.\n", logfile_name)
		else if (OPT_IS("response_dir")) OPT_SET("  Loading default responses from %s.\n", response_dir)
		else if (OPT_IS("plugin_dir")) OPT_SET("  Loading plugins from %s.\n", plugin_dir)
		else if (OPT_IS("bind_address")) {
			if (inet_aton(value, &bind_address) == 0) {
				fprintf(stderr, "  Error - Unable to convert IP address: %s.\n", strerror(errno));
				exit(EXIT_FAILURE);
			}
			DEBUG_FPRINTF(stdout, "  Binding dynamic servers to %s.\n", inet_ntoa(bind_address));
		}
		else if (OPT_IS("user")) {
			if ((pwd_entry = getpwnam(value)) == NULL) {
				if (errno) fprintf(stderr, "  Error - Invalid user '%s': %m.\n", value);
				else fprintf(stderr, "  Error - User %s not found.\n", value);
				exit(EXIT_FAILURE);
			}
			u_id = pwd_entry->pw_uid;
			user = value;
			DEBUG_FPRINTF(stdout, "  Setting user to %ss\n", user);
		} else if (OPT_IS("group")) {
			if ((grp_entry = getgrnam(value)) == NULL) {
				if (errno) fprintf(stderr, "  Error - Invalid group '%s': %m.\n", value);
				else fprintf(stderr, "  Error - Group %s not found.\n", value);
				exit(EXIT_FAILURE);
			}
			g_id = grp_entry->gr_gid;
			group = value;
			DEBUG_FPRINTF(stdout, "  Setting group to %s.\n", group);
		} else if (OPT_IS("portconf")) {
			if (process_conftree(node, node->first_leaf, process_confopt_portconf, NULL) == NULL) return(NULL);
			node->first_leaf = NULL;
			conftree_children_free(node);
		} else {
			fprintf(stderr, "  Error - Invalid keyword in configuration file: %s\n", node->keyword);
			exit(EXIT_FAILURE);
		}
		if (node->val) node->val = node->val->next;
	} while (node->val);

	return(node);
}


conf_node *process_confopt_portconf(conf_node *tree, conf_node *node, void *opt_data) {
	char		*value		= NULL;
	conf_node	*confopt	= NULL;
	portcfg		*pconf		= NULL;
	struct portmap	*portmap	= NULL;
	struct protomap	*protomap	= NULL;
	struct pconfmap	*pmap		= NULL,
			*old_map	= NULL,
			*cur_map	= NULL;
	u_char		mode		= 0;

	if ((confopt = check_keyword(tree, node->keyword)) == NULL) return(NULL);

	/* do instead of while because we can have nodes without values here */
	do {
		if (node->val) {
			if ((value = malloc(node->val->size+1)) == NULL) {
				perror("  Error - Unable to allocate memory");
				exit(EXIT_FAILURE);
			}
			memset(value, 0, node->val->size+1);
			memcpy(value, node->val->data, node->val->size);
		}

		/* prepare config map */
		if ((pmap = (struct pconfmap *) malloc(sizeof(struct pconfmap))) == NULL) {
			perror("  Error - Unable to allocate memory");
			exit(EXIT_FAILURE);
		}
		memset(pmap, 0, sizeof(struct pconfmap));

		if OPT_IS("ignore") {
			mode = PORTCONF_IGNORE;
			process_conftree(node, node->first_leaf, process_confopt_portconf_simple, pmap);
			node->first_leaf = NULL;
			conftree_children_free(node);
		} else if OPT_IS("mirror") {
			mode = PORTCONF_MIRROR;
			process_conftree(node, node->first_leaf, process_confopt_portconf_simple, pmap);
			node->first_leaf = NULL;
			conftree_children_free(node);
		} else if OPT_IS("normal") {
			mode = PORTCONF_NORMAL;
			process_conftree(node, node->first_leaf, process_confopt_portconf_simple, pmap);
			node->first_leaf = NULL;
			conftree_children_free(node);
		} else if OPT_IS("proxy") {
			mode = PORTCONF_PROXY;
			process_conftree(node, node->first_leaf, process_confopt_portconf_proxy, pmap);
			node->first_leaf = NULL;
			conftree_children_free(node);
		} else {
			fprintf(stderr, "  Error - Invalid keyword in configuration file: %s\n", node->keyword);
			exit(EXIT_FAILURE);
		}
		
		cur_map = pmap;
		while (cur_map) {
			protomap = cur_map->protomap;
			while (protomap) {
				portmap = cur_map->portmap;
				while (portmap) {
					/* prepare port configuration */
					if ((pconf = (portcfg *) malloc(sizeof(portcfg))) == NULL) {
						perror("  Error - Unable to allocate memory");
						exit(EXIT_FAILURE);
					}
					memset(pconf, 0, sizeof(portcfg));
					pconf->mode	= mode;
					pconf->target	= cur_map->target;
					pconf->port	= portmap->port;
					pconf->protocol	= protomap->protocol;

					/* set poiner in port configuration array */
					if (pconf->protocol == TCP) {
						if (port_flags_tcp[pconf->port]) {
							fprintf(stderr, "  Error - Duplicate configuration for port %d/tcp.\n", pconf->port);
							return(NULL);
						}
						port_flags_tcp[pconf->port] = pconf;
					} else if (pconf->protocol == UDP) {
						if (port_flags_udp[pconf->port]) {
							fprintf(stderr, "  Error - Duplicate configuration for port %d/udp.\n", pconf->port);
							return(NULL);
						}
						port_flags_udp[pconf->port] = pconf;
					} else {
						fprintf(stderr, "  Error - Invalid protocol type for port %d.\n", pconf->port);
						return(NULL);
					}
					if (mode == PORTCONF_PROXY) {
						if (pconf->target == NULL) {
							fprintf(stderr, "  Error - Proxy target for port %d/%s missing.\n",
								pconf->port, PROTO(pconf->protocol));
							return(NULL);
						}
						printf("  Port %d/%s is configured to be handled in %s mode with target %s:%d/%s.\n",
							pconf->port, PROTO(pconf->protocol), MODE(pconf->mode),
							pconf->target->host, pconf->target->port, PROTO(pconf->target->protocol));
					} else {
						printf("  Port %d/%s is configured to be handled in %s mode.\n",
							pconf->port, PROTO(pconf->protocol), MODE(pconf->mode));
					}
						
					portmap = portmap->next;
				}
				protomap = protomap->next;
			}
			old_map = cur_map;
			cur_map = cur_map->next;
			free(old_map);
		}

		if (node->val) node->val = node->val->next;
	} while (node->val);

	return(node);
}


conf_node *process_confopt_portconf_proxy(conf_node *tree, conf_node *node, void *pmap) {
	int		i;
	conf_node	*map		= NULL;
	struct pconfmap	*pmap_new	= NULL;

	/* got a proxy map, check map names manually and then parse subtrees */
	map = node;
	while (map) {
		if (((struct pconfmap *)pmap) == NULL) {
			fprintf(stderr, "  Error - Could not add proxy target configuration: No map given.\n");
			exit(EXIT_FAILURE);
		}

		/* only [a-zA-Z-_] map names are allowed */
		for (i=0; i<strlen(map->keyword); i++) {
			if (!isalnum(map->keyword[i]) && (map->keyword[i] != '-') && (map->keyword[i] != '_')) {
				fprintf(stderr, "  Error - Invalid proxy map name (use [a-zA-Z-_]: %s\n", map->keyword);
				return(NULL);
			}
		}

		/* prepare proxy map configuration */
		if ((((struct pconfmap *)pmap)->target = (proxy_dest *) malloc(sizeof(proxy_dest))) == NULL) {
			perror("  Error - Unable to allocate memory");
			exit(EXIT_FAILURE);
		}
		memset(((struct pconfmap *)pmap)->target, 0, sizeof(proxy_dest));
		process_conftree(node, map->first_leaf, process_confopt_portconf_proxy_map, (void *) pmap);

		if ((node = map->next) != NULL) {
			/* prepare new config map */
			if ((pmap_new = (struct pconfmap *) malloc(sizeof(struct pconfmap))) == NULL) {
				perror("  Error - Unable to allocate memory");
				exit(EXIT_FAILURE);
			}
			memset(pmap_new, 0, sizeof(struct pconfmap));
			((struct pconfmap *)pmap)->next = pmap_new;
			pmap = ((struct pconfmap *)pmap)->next;
		}
		conftree_children_free(map);
		map = node;
	}

	return(node);
}


conf_node *process_confopt_portconf_simple(conf_node *tree, conf_node *node, void *pmap) {
	char		*value = NULL;
	conf_node	*confopt = NULL;
	struct portmap	*port_new = NULL,
			*portmap = ((struct pconfmap *)pmap)->portmap;
	struct protomap	*proto_new = NULL,
			*protomap = ((struct pconfmap *)pmap)->protomap;

	if ((confopt = check_keyword(tree, node->keyword)) == NULL) return(NULL);

	while (node->val) {
		if ((value = malloc(node->val->size+1)) == NULL) {
			perror("  Error - Unable to allocate memory");
			exit(EXIT_FAILURE);
		}
		memset(value, 0, node->val->size+1);
		memcpy(value, node->val->data, node->val->size);

		if (((struct pconfmap *)pmap) == NULL) {
			fprintf(stderr, "  Error - Could not add simple port configuration: No map given.\n");
			exit(EXIT_FAILURE);
		}

		if (OPT_IS("port")) {
			if ((port_new = (struct portmap *) malloc(sizeof(struct portmap))) == NULL) {
				perror("  Error - Unable to allocate memory");
				exit(EXIT_FAILURE);
			}
			memset(port_new, 0, sizeof(struct portmap));
			port_new->port = atoi(value);
			free(value);

			/* append new port to list */
			if ((portmap = ((struct pconfmap *)pmap)->portmap) == NULL) {
				((struct pconfmap *)pmap)->portmap = port_new;
			} else {
				while (portmap->next) portmap = portmap->next;
				portmap->next = port_new;
			}
		} else if OPT_IS("protocol") {
			if ((proto_new = (struct protomap *) malloc(sizeof(struct protomap))) == NULL) {
				perror("  Error - Unable to allocate memory");
				exit(EXIT_FAILURE);
			}
			memset(proto_new, 0, sizeof(struct protomap));
			if (strncmp(value, "tcp", 3 < strlen(value) ? 3 : strlen(value)) == 0) proto_new->protocol = TCP;
			else if (strncmp(value, "udp", 3 < strlen(value) ? 3 : strlen(value)) == 0) proto_new->protocol = UDP;
			free(value);

			/* append new protocol to list */
			if ((protomap = ((struct pconfmap *)pmap)->protomap) == NULL) {
				((struct pconfmap *)pmap)->protomap = proto_new;
			} else {
				while (protomap->next) protomap = protomap->next;
				protomap->next = proto_new;
			}
		} else {
			fprintf(stderr, "  Error - Invalid keyword in configuration file: %s\n", node->keyword);
			exit(EXIT_FAILURE);
		}

		node->val = node->val->next;
	}
	return(node);
}


conf_node *process_confopt_portconf_proxy_map(conf_node *tree, conf_node *node, void *pmap) {
	char		*value = NULL;
	conf_node	*confopt = NULL;
	struct portmap	*port_new = NULL,
			*portmap = ((struct pconfmap *)pmap)->portmap;
	struct protomap	*proto_new = NULL,
			*protomap = ((struct pconfmap *)pmap)->protomap;

	if ((confopt = check_keyword(tree, node->keyword)) == NULL) return(NULL);

	while (node->val) {
		if ((value = malloc(node->val->size+1)) == NULL) {
			perror("  Error - Unable to allocate memory");
			exit(EXIT_FAILURE);
		}
		memset(value, 0, node->val->size+1);
		memcpy(value, node->val->data, node->val->size);

		if (((struct pconfmap *)pmap) == NULL) {
			fprintf(stderr, "  Error - Could not add proxy port configuration: No map given.\n");
			exit(EXIT_FAILURE);
		}

		if (OPT_IS("port")) {
			if ((port_new = (struct portmap *) malloc(sizeof(struct portmap))) == NULL) {
				perror("  Error - Unable to allocate memory");
				exit(EXIT_FAILURE);
			}
			memset(port_new, 0, sizeof(struct portmap));
			port_new->port = atoi(value);
			free(value);

			/* append new port to list */
			if ((portmap = ((struct pconfmap *)pmap)->portmap) == NULL) {
				((struct pconfmap *)pmap)->portmap = port_new;
			} else {
				while (portmap->next) portmap = portmap->next;
				portmap->next = port_new;
			}
		} else if (OPT_IS("protocol")) {
			if ((proto_new = (struct protomap *) malloc(sizeof(struct protomap))) == NULL) {
				perror("  Error - Unable to allocate memory");
				exit(EXIT_FAILURE);
			}
			memset(proto_new, 0, sizeof(struct protomap));
			if (strncmp(value, "tcp", 3 < strlen(value) ? 3 : strlen(value)) == 0) proto_new->protocol = TCP;
			else if (strncmp(value, "udp", 3 < strlen(value) ? 3 : strlen(value)) == 0) proto_new->protocol = UDP;
			free(value);

			/* append new protocol to list */
			if ((protomap = ((struct pconfmap *)pmap)->protomap) == NULL) {
				((struct pconfmap *)pmap)->protomap = proto_new;
			} else {
				while (protomap->next) protomap = protomap->next;
				protomap->next = proto_new;
			}
		} else if (OPT_IS("target_host")) {
			((struct pconfmap *)pmap)->target->host = value;
		} else if (OPT_IS("target_port")) {
			((struct pconfmap *)pmap)->target->port = atoi(value);
			free(value);
		} else if (OPT_IS("target_protocol")) {
			if (strncmp(value, "tcp", 3 < strlen(value) ? 3 : strlen(value)) == 0) ((struct pconfmap *)pmap)->target->protocol = TCP;
			else if (strncmp(value, "udp", 3 < strlen(value) ? 3 : strlen(value)) == 0) ((struct pconfmap *)pmap)->target->protocol = UDP;
			free(value);
		} else {
			fprintf(stderr, "  Error - Invalid keyword in configuration file: %s\n", node->keyword);
			exit(EXIT_FAILURE);
		}
		node->val = node->val->next;
	}
	return(node);
}


conf_node *process_confopt_plugin(conf_node *tree, conf_node *node, void *opt_data) {
	char		*value = NULL;
	conf_node	*confopt = NULL;

	/* just check whether all keywords are registered and set values
	 * evaluation is performed by the plugin itself */

	if ((confopt = check_keyword(tree, node->keyword)) == NULL) return(NULL);

	while (node->val) {
		if ((value = malloc(node->val->size+1)) == NULL) {
			perror("  Error - Unable to allocate memory");
			exit(EXIT_FAILURE);
		}
		memset(value, 0, node->val->size+1);
		memcpy(value, node->val->data, node->val->size);

		node->val = node->val->next;
	}
	return(node);
}
