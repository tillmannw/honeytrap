/* signals.c
 * Copyright (C) 2005-2007 Tillmann Werner <tillmann.werner@gmx.de>
 *
 * This file is free software; as a special exception the author gives
 * unlimited permission to copy and/or distribute it, with or without
 * modifications, as long as this notice is preserved.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
 * implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */

#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>

#include "logging.h"
#include "honeytrap.h"
#include "ctrl.h"
#include "readconf.h"
#include "plugin.h"
#include "signals.h"

#define MASTER_PROCESS (pid = getpid()) == parent_pid


void handle_signal(int sig) {
	pid_t pid;

	switch(sig) {
		case SIGHUP:
			if (MASTER_PROCESS) {
				logmsg(LOG_DEBUG, 1, "SIGHUP received. Reconfiguring honeytrap.\n");

				/* unloading plugins */
				unload_plugins();
				
				/* configure honeytrap */
				logmsg(LOG_NOTICE, 1, "---- Reloading configuration ----\n");
				configure(arg_c, arg_v);

				logmsg(LOG_NOTICE, 1, "---- honeytrap reconfigured ----\n");
			}
			break;
		case SIGSEGV:
			logmsg(LOG_ERR, 1, "Error - Segmentation fault (SIGSEGV received).\n");
			_exit(EXIT_FAILURE);
		case SIGINT:
			logmsg(LOG_DEBUG, 1, "SIGINT received.\n");
			if (MASTER_PROCESS) {
				if (kill(0-getpgrp(), SIGINT) == 0) {
					logmsg(LOG_DEBUG, 1, "SIGINT was successfully sent to process group.\n");
					/* wait for children */
					while ((pid = waitpid(-1, 0, WNOHANG)) > 0) logmsg(LOG_DEBUG, 1, "Process %d terminated.\n", pid);
				} else {
					logmsg(LOG_ERR, 1, "Error sending SIGINT to process group.\n");
					clean_exit(EXIT_FAILURE);
				}
				clean_exit(EXIT_SUCCESS);
			} else _exit(EXIT_SUCCESS);
		case SIGQUIT:
			logmsg(LOG_DEBUG, 1, "SIGQUIT received.\n");
			if (MASTER_PROCESS) {
				if (kill(0-getpgrp(), SIGQUIT) == 0)
					logmsg(LOG_DEBUG, 1, "SIGQUIT was successfully sent to process group.\n");
				else {
					logmsg(LOG_ERR, 1, "Error sending SIGQUIT to process group.\n");
					clean_exit(EXIT_FAILURE);
				}
				clean_exit(EXIT_SUCCESS);
			} else _exit(EXIT_SUCCESS);
		case SIGTERM:
			logmsg(LOG_DEBUG, 1, "SIGTERM received.\n");
			if (MASTER_PROCESS) {
				if (kill(0-getpgrp(), SIGTERM) == 0) {
					logmsg(LOG_DEBUG, 1, "SIGTERM was successfully sent to process group.\n");
					/* wait for children */
					while ((pid = waitpid(-1, 0, WNOHANG)) > 0) logmsg(LOG_DEBUG, 1, "Process %d terminated.\n", pid);
				} else {
					logmsg(LOG_ERR, 1, "Error sending SIGTERM to process group.\n");
					clean_exit(EXIT_FAILURE);
				}
				clean_exit(EXIT_SUCCESS);
			} else _exit(EXIT_SUCCESS);
		case SIGCHLD:
			logmsg(LOG_DEBUG, 1, "SIGCHILD received.\n");
			while ((pid = waitpid(-1, NULL, WNOHANG)) > 0) logmsg(LOG_DEBUG, 1, "Process %d terminated.\n", pid);
			break;
		default:
			break;
	}
	return;
}


void install_signal_handlers(void) {
	/* install signal handlers */
	if (signal(SIGHUP, handle_signal) == SIG_ERR)
		fprintf(stdout, "  Warning - Handler for SIGHUP was not installed for %u.\n", getpid());
	else DEBUG_FPRINTF(stdout, "  Signal handler for SIGHUP installed.\n");
	
	if (signal(SIGSEGV, handle_signal) == SIG_ERR)
		fprintf(stdout, "  Warning - Handler for SIGSEGV was not installed for %u.\n", getpid());
	else DEBUG_FPRINTF(stdout, "  Signal handler for SIGSEGV installed.\n");
	
	if (signal(SIGINT, handle_signal) == SIG_ERR) 
		fprintf(stdout, "  Warning - Handler for SIGINT was not installed for %u.\n", getpid());
	else DEBUG_FPRINTF(stdout, "  Signal handler for SIGINT installed.\n");

	if (signal(SIGQUIT, handle_signal) == SIG_ERR) 
		fprintf(stdout, "  Warning - Handler for SIGQUIT was not installed for %u.\n", getpid());
	else DEBUG_FPRINTF(stdout, "  Signal handler for SIGQUIT installed.\n");
	
	if (signal(SIGTERM, handle_signal) == SIG_ERR)
		fprintf(stdout, "  Warning - Handler for SIGTERM was not installed for %u.\n", getpid());
	else DEBUG_FPRINTF(stdout, "  Signal handler for SIGTERM installed.\n");

	if (signal(SIGCHLD, handle_signal) == SIG_ERR)
		fprintf(stdout, "  Warning - Handler for SIGCHLD was not installed for %u.\n", getpid());
	else DEBUG_FPRINTF(stdout, "  Signal handler for SIGCHLD installed.\n");

	return;
}

