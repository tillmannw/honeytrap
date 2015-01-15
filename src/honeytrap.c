/* honeytrap.c
 * Copyright (C) 2005-2015 Tillmann Werner <tillmann.werner@gmx.de>
 *
 * This file is free software; as a special exception the author gives
 * unlimited permission to copy and/or distribute it, with or without
 * modifications, as long as this notice is preserved.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
 * implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */

#include <stdlib.h>
#include <netdb.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include "connectmon.h"
#include "ctrl.h"
#include "dynsrv.h"
#include "event.h"
#include "honeytrap.h"
#ifdef USE_IPQ_MON
  #include "ipqmon.h"
#endif
#include "logging.h"
#ifdef USE_PCAP_MON
  #include "pcapmon.h"
#endif
#include "plughook.h"
#include "plugin.h"
#include "queue.h"
#include "readconf.h"
#include "response.h"
#include "signals.h"


int main(int argc, char **argv) {
	/* initial configuration, will be overridden by config file and command line options  */

	first_init	= 1;
	running		= 0;	// will be set to != 0 once honeytrap set up itself

	/* save command line arguments */
	arg_c = argc;
	arg_v = argv;


	/* the following are default values - change them in your configuration file */
	
	daemonize		= 1;		// default is to daemonize

#ifdef USE_PCAP_MON
	promisc_mode		= 0;		// no promisc mode
	pcap_offset		= 0;		// will be set after link type is determined
#endif

	log_level		= LOG_NOTICE;	// default log level
	logfile_fd		= STDOUT_FILENO;// default logfile, stdout will be replaced by logfile_fd
	
	u_id			= 0;		// root privileges per default
	g_id			= 0;

	conn_timeout		= 120;		// 2 minutes connect timeout
	read_timeout		= 1;		// 1 second read timeout
	m_read_timeout		= 60;		// 1 minute read timeout for mirror connections
	read_limit		= 0;		// 0 means no read limit
	
	conffile_name		= strdup("/etc/honeytrap/honeytrap.conf");
	pidfile_name		= strdup("/var/run/honeytrap.pid");
	logfile_name		= strdup("/var/log/honeytrap.log");
	response_dir		= strdup("/etc/honeytrap/responses");
	plugin_dir		= strdup("/etc/honeytrap/plugins");

#ifdef USE_PCAP_MON
	dev			= NULL;		// network device pointer
	packet_sniffer		= NULL;		// pcap device pointer
#endif

	portconf_default	= PORTCONF_NONE;

	eventlist		= NULL;		// list of timer-based events


	/* configure honeytrap */
	configure(arg_c, arg_v);

	
	/* daemonize (detach from console) */
	if (daemonize) do_daemonize();


	/* now initialize plugins */
	init_plugins();


	/* create pid file */
	create_pid_file();


	/* create IPC pipe and queue for port infos */
	if (pipe(portinfopipe) == -1) {
		logmsg(LOG_ERR, 0, "  Error - Unable to create port info IPC pipe: %m.\n");
		exit(EXIT_FAILURE);
	}
	if ((portinfoq = queue_new()) == NULL) {
		logmsg(LOG_ERR, 0, "  Error - Unable to create port info IPC pipe: %m.\n");
		exit(EXIT_FAILURE);
	}

	
	/* watch out for incoming connection requests */
	if (start_connection_monitor() < 0) clean_exit(EXIT_SUCCESS);
	
	return(0);
}
