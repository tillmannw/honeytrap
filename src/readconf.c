/* readconf.c
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
#include "honeytrap.h"
#include "logging.h"
#include "response.h"
#include "ctrl.h"
#include "signals.h"
#include "plugin.h"
#include "pcapmon.h"
#include "ipqmon.h"

#ifdef USE_PCAP_MON
  #define OPTSTRING	"vh?pDmL:P:C:i:a:l:r:u:g:t:"
#else
  #define OPTSTRING	"vh?pDmL:P:C:l:r:u:g:t:"
#endif

#define OPT_IS(A)	(strcmp(low_opt, (A)) == 0)

char *get_next_line(FILE * file) {
	/* return next line from file */

	char buf[BUFSIZ];
	char *index;

	bzero((char *)buf, BUFSIZ);

	while(fgets(buf, BUFSIZ, file)) {
		index = buf;
		/* advance through whitespaces at the beginning of the line */
		while (isspace((int) *index)) ++index;

		return((char *) strdup(index));
	}
	return(NULL);
}


void *get_value(char *buf, const char delim) {
	/* find delimiter in string and overwrite it with \0 to terminate keywort,
	 * skip following whitespaces and return pointer to the found value
	 * return NULL if delimiter is not found */

	char *index, *retval = NULL;

	/* search for delimiter */
	if ((retval = strchr(buf, delim)) == NULL) return(NULL);

	/* overwrite delimiter to terminate keyword */
	retval[0] = '\0';
	retval++;
	index = buf;
	/* cut trailing blanks */
	while (!isspace((int) *index) && strlen(index)) index++;
	index[0] = '\0';

	/* strip leading whitespaces */
	while (isspace((int) *retval)) retval++;
	/* cut trailing blanks */
	index = retval;
	while (!isspace((int) *index) && strlen(index)) index++;
	index[0] = '\0';

	return(retval);
}


int configure(int my_argc, char *my_argv[]) {
#ifdef USE_PCAP_MON
	char *bpf_cmd_ext, errbuf[PCAP_ERRBUF_SIZE];
	struct hostent *ip_cmd_opt;
#endif
	char option;
	struct passwd *pwd_entry;
	struct group *grp_entry;

	/* initialilzation of variables */
	default_response	= NULL;	/* initialize default response list */
	proxy_dest		= NULL;	/* list with destinations for ports which are handled in proxy mode */
	pidfile_fd		= 0;
#ifdef USE_PCAP_MON
	bpf_cmd_ext		= NULL;	/* bpf string extension ('expression' from command line) */
	ip_cmd_opt		= NULL;	/* source ip address for bpf string */
#endif

	/* initialize port flags array with zeros */
	bzero(port_flags, 0x10000); 


	/* scan command line options to determine logging level or print version number or usage */
	while((option = getopt(my_argc, my_argv, OPTSTRING)) > 0) {
		switch(option) {
			case 't':
				if ((atoi(optarg) < 7) && (atoi(optarg) >= 0)) log_level = atoi(optarg);
				else {
					fprintf(stderr, "  Error - Log level must be a value between 0 and 6.\n");
					exit(1);
				}
				break;
			case 'v':
				fprintf(stdout, "%s\n", PACKAGE_STRING);
				exit(0);
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
			DEBUG_FPRINTF(stderr, "  Warning - Unable to determine current working directory.\n");
			exit(1);
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
	if (parse_config_file(conffile_name) == -1) {
		fprintf(stderr, "  Error - Unable to parse configuration file %s.\n", conffile_name);
		exit(1);
	}


	if (first_init) {	
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
						fprintf(stderr, "  Error - Invalid hostname or ip address.\n");
						exit(1);
					}
					break;
				case 'p':
					promisc_mode = 1;
					break;
#endif
				case 'm':
					mirror_mode = 1;
					break;
				case 'l':
					conn_timeout = strtoul(optarg, NULL, 0);
					if((conn_timeout < 0) || (conn_timeout > 255)) {
						fprintf(stderr,
							"  Error - Listen timeout must be a value between 0 and 255.\n");
						exit(1);
					}
					break;
				case 'r':
					read_timeout = strtoul(optarg, NULL, 0);
					if((read_timeout < 0) || (read_timeout > 255)) {
						fprintf(stderr,
							"  Error - Read timeout must be a value between 0 and 255.\n");
						exit(1);
					}
					break;
				case 'u':
					if ((pwd_entry = getpwnam(optarg)) == NULL) {
						if (errno) fprintf(stderr, "  Invalid user: %s\n", strerror(errno));
						else fprintf(stderr, "  User %s not found.\n", optarg);
						exit(0);
					} else {
						u_id = pwd_entry->pw_uid;
						user = strdup(optarg);
					}
					break;
				case 'g':
					if ((grp_entry = getgrnam(optarg)) == NULL) {
						if (errno) fprintf(stderr, "  Invalid group: %s\n", strerror(errno));
						else fprintf(stderr, "  Group %s not found.\n", optarg);
						exit(0);
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
				fprintf(stderr, "  Error - Unable to determine default network interface.\n");
				fprintf(stderr, "  Error - No interface given.\n");
				exit(1);
			}
			fprintf(stdout, "  Default device is %s.\n", dev);
		}
#endif
	}

	fprintf(stdout, "  Servers will run as user %s (%d).\n", user, u_id);
	fprintf(stdout, "  Servers will run as group %s (%d).\n", group, g_id);


	/* load plugins */
	load_plugins(plugin_dir);


	/* load default responses */
	if (response_dir) {
		if (load_default_responses(response_dir) == -1)
			fprintf(stdout, "  Warning - Unable to load default responses.\n");
	}


	if(mirror_mode) fprintf(stdout,"  Mirror mode enabled.\n");


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
					fprintf(stderr,
						"  Error - Unable to allocate memory: %s\n", strerror(errno));
					exit(1);
				}
				snprintf(bpf_cmd_ext+strlen(bpf_cmd_ext), strlen(my_argv[optind])+2,
					" %s%c", my_argv[optind], 0);
			}
			my_argv[optind++];
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


	/* install signal handlers */
	install_signal_handlers();
	

	/* open logfile */
	if((logfile_fd = open(logfile_name, EXCL_FILE_RW, 0644)) == -1) {
		fprintf(stderr, "  Error - Unable to open logfile.\n");
		exit(1);
	}
	fprintf(stdout, "  Logging to %s.\n", logfile_name);


	fprintf(stdout, "  Initialization complete.\n");
	logmsg(LOG_ERR, 0, "\nhoneytrap v%s Copyright (C) 2005-2006 Tillmann Werner <tillmann.werner@gmx.de>\n", VERSION);

	first_init = 0;
	return(1);
}


int parse_config_file(const char *filename) {
	char *recvline, *config_opt, *config_val;
	int config_file_fd, line_number;
	FILE *config_file;

	line_number		= 0;
	recvline		= NULL;
	config_opt		= NULL;
	config_val		= NULL;


	if((config_file_fd = open(filename, 0, 0640)) == -1) return(-1);

	/* lock config file to prevent include loops */
	if (flock(config_file_fd, LOCK_EX | LOCK_NB) != 0) {
		fprintf(stderr, "  Error - Unable to lock configuration file: %s\n", strerror(errno));
		return(-1);
	}

	/* reopen config file as stream to be able to use fgets() */
	if ((config_file = fdopen(config_file_fd, "r")) == NULL) {
		fprintf(stderr, "  Error - Unable to open configuration file: %s\n", strerror(errno));
		return(-1);
	}

	DEBUG_FPRINTF(stdout, "  Config file parser - File reopened as stream, ready to parse.\n");

	while((recvline = get_next_line(config_file)) > 0) {
		line_number++;
		
		/* ignore comments and blank lines */
		if ((*recvline == '#') || (*recvline == 0x0a) || (*recvline == 0x00) || (recvline == NULL)) continue;

		/* remove newlines */
		if ((recvline)[strlen(recvline)-1] == '\n') recvline[strlen(recvline)-1] = 0;
		DEBUG_FPRINTF(stdout, "  Config file parser - Line %u in %s: %s\n", line_number, filename, recvline);

		config_opt = recvline;
		if ((config_val = get_value(recvline, '=')) == NULL) {
			if ((config_opt)[strlen(config_opt)-1] == '\n') config_opt[strlen(config_opt)-1] = 0;
		}
		if (process_config_option(config_opt, config_val) == -1) {
			fprintf(stderr, "  Error - Invalid line %u in file %s.\n", line_number, filename); 
			return(-1);
		}
	}
	DEBUG_FPRINTF(stdout, "  Config file parser - %u lines successfully parsed.\n", line_number); 

	if (flock(config_file_fd, LOCK_UN) != 0) fprintf(stderr, "  Error - Unable to unlock configuration file: %s\n",
		strerror(errno));
	if (fclose(config_file) == EOF) fprintf(stderr, "  Error - Unable to close configuration file: %s\n",
		strerror(errno));
	
	return(0);
}

int process_config_option(char *opt, char* val) {
	char *index, *low_opt, *portnum, *portconf, *d_addr, *port_str;
	struct passwd *pwd_entry;
	struct group *grp_entry;
	uint16_t d_port;
	struct s_proxy_dest *pd_tmp, *pd_new;

	portnum		= NULL;
	portconf	= NULL;
	low_opt		= NULL;
	d_addr		= NULL;
	d_port		= 0;


	/* turn keywords into lowercase */
	low_opt			= (char *) strdup(opt);
	index			= low_opt;
	while(*index != '\0') tolower(*index++);


	if (OPT_IS("include")) {
		/* include line found, do recursive processing */
		DEBUG_FPRINTF(stdout, "  Including configuration from %s.\n", val);
		if (parse_config_file(val) == -1) {
			fprintf(stderr, "  Error - Unable to parse configuration file %s.\n", val);
			exit(1);
		}
		return(0);
	}

	if (OPT_IS("mirror")) {
		mirror_mode = 1;
		DEBUG_FPRINTF(stdout, "  Activating mirror mode.\n");
#ifdef USE_PCAP_MON
	} else if (OPT_IS("promisc")) {
		promisc_mode = 1;
		DEBUG_FPRINTF(stdout, "  Activating promiscuous mode.\n");
#endif
	} else if (OPT_IS("read_limit")) {
		read_limit = atol(val);
		DEBUG_FPRINTF(stdout, "  Setting read limit to %d.\n", read_limit);
	} else if (OPT_IS("pidfile")) {
		free(pidfile_name);
		pidfile_name = strdup(val);
		DEBUG_FPRINTF(stdout, "  Pid file is %s.\n", val);
	} else if (OPT_IS("logfile")) {
		free(logfile_name);
		logfile_name = strdup(val);
		DEBUG_FPRINTF(stdout, "  Logfile is %s.\n", val);
	} else if (OPT_IS("dbfile")) {
		free(dbfile_name);
		dbfile_name = strdup(val);
		DEBUG_FPRINTF(stdout, "  Databse file is %s.\n", val);
	} else if (OPT_IS("response_dir")) {
		free(response_dir);
		response_dir = strdup(val);
		DEBUG_FPRINTF(stdout, "  Loading default responses from %s.\n", val);
	} else if (OPT_IS("plugin_dir")) {
		free(plugin_dir);
		plugin_dir = strdup(val);
		DEBUG_FPRINTF(stdout, "  Loading plugins from %s.\n", val);
	} else if (OPT_IS("attacks_dir")) {
		free(attacks_dir);
		attacks_dir = strdup(val);
		DEBUG_FPRINTF(stdout, "  Storing attack strings in %s.\n", val);
	} else if (OPT_IS("dlsave_dir")) {
		free(dlsave_dir);
		dlsave_dir = strdup(val);
		DEBUG_FPRINTF(stdout, "  Storing downloaded files in %s.\n", val);
	} else if (OPT_IS("user")) {
		if ((pwd_entry = getpwnam(val)) == NULL) {
			if (errno) fprintf(stderr, "  Invalid user in configuration file: %s\n", strerror(errno));
			else fprintf(stderr, "  User %s not found.\n", val);
			exit(0);
		} else {
			u_id = pwd_entry->pw_uid;
			user = strdup(val);
		}
	} else if (OPT_IS("group")) {
		if ((grp_entry = getgrnam(val)) == NULL) {
			if (errno) fprintf(stderr, "  Invalid group in configuration file: %s\n", strerror(errno));
			else fprintf(stderr, "  Group %s not found.\n", val);
			exit(0);
		} else {
			g_id = grp_entry->gr_gid;
			group = strdup(val);
		}
	} else if (OPT_IS("port")) {
		if ((portconf = get_value(val, ',')) != NULL) {
			if (strcmp(portconf, "normal") == 0) {
				port_flags[atoi(val)] = PORTCONF_NORMAL;
				fprintf(stdout, "  Connections to port %u/tcp will be handled in normal mode.\n",atoi(val));
			} else if (strcmp(portconf, "ignore") == 0) {
				port_flags[atoi(val)] = PORTCONF_IGNORE;
				fprintf(stdout, "  Connections to port %u/tcp will be ignored.\n", atoi(val));
			} else if (strcmp(portconf, "mirror") == 0) {
				port_flags[atoi(val)] = PORTCONF_MIRROR;
				fprintf(stdout, "  Connections to port %u/tcp will be handled in mirror mode.\n",atoi(val));
			} else if (strncmp(portconf, "proxy", 5) == 0) {
				port_flags[atoi(val)] = PORTCONF_PROXY;
				if ((d_addr = get_value(portconf, ',')) != NULL) {
					if ((port_str = get_value(d_addr, ':')) != NULL)
						d_port = atoi(port_str);
					else d_port = atoi(val);
				} else {
					fprintf(stderr, "  Invalid port configuration, no proxy destination found.\n");
					exit(0);
				}

				/* create new proxy destination list entry */
				if ((pd_new = (struct s_proxy_dest*) malloc(sizeof(struct s_proxy_dest))) == NULL) {
					logmsg(LOG_ERR, 1, "    Error - Unable to allocate memory: %s\n", strerror(errno));
					return(-1);
				}
				pd_new->next = NULL;

				/* attach new function to list */
				pd_tmp = proxy_dest;
				if (pd_tmp) {
					while(pd_tmp->next) pd_tmp = pd_tmp->next;
					pd_tmp->next = pd_new;
				} else proxy_dest = pd_new;

				pd_new->attack_port	= atoi(val);
				pd_new->d_addr		= strdup(d_addr);
				pd_new->d_port		= d_port;

				fprintf(stdout, "  Connections to port %u/tcp will be handled in 'proxy' mode (to %s:%u/tcp).\n", pd_new->attack_port, pd_new->d_addr, pd_new->d_port);
			} else {
				fprintf(stderr, "  Invalid port configuration.\n");
				exit(0);
			}
		} else {
			fprintf(stderr, "  Invalid port configuration.\n");
			exit(0);
		}
	} else {
		fprintf(stderr, "  Error - Invalid keyword '%s' in configuration file.\n", opt);
		return(-1);
	}

	free(low_opt);

	return(0);
}
