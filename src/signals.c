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

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "logging.h"
#include "honeytrap.h"
#include "ctrl.h"
#include "readconf.h"
#include "plugin.h"
#include "plughook.h"
#include "signals.h"

#define MASTER_PROCESS (pid = getpid()) == parent_pid


void get_signal(int sig) {
	switch (sig) {
	case SIGINT:
	case SIGHUP:
	case SIGQUIT:
	case SIGTERM:
	case SIGCHLD:
		/* prevent nested interrupts */
		if (signal(sig, SIG_IGN) == SIG_IGN) return;
		break;
	default:
		break;
	}
	if (write(sigpipe[1], (char *) &sig, sizeof(int)) == -1) {
		write(logfile_fd, "Error - Unable to write signal to pipe.\n", 40);
		if ((STDOUT_FILENO != logfile_fd) && (daemonize != 1))
			write(STDOUT_FILENO, "Error - Unable to write signal to pipe.\n", 40);
		exit(EXIT_FAILURE);
	}
	return;
}


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

		/* reinstall original signal handler */
		if (signal(SIGHUP, get_signal) == SIG_ERR)
			logmsg(LOG_ERR, 1, "Error - Unable to reinstall signal handler for SIGHUP.\n");
		else logmsg(LOG_DEBUG, 1, "Signal handler for SIGHUP reinstalled.\n");
	
		break;
	case SIGSEGV:
		if (current_plugfunc)
			logmsg(LOG_ERR, 1, "Error - Segmentation fault in process %d, %s::%s()  (SIGSEGV received).\n",
				getpid(), current_plugfunc->plugnam, current_plugfunc->funcnam);
		else 
			logmsg(LOG_ERR, 1, "Error - Segmentation fault in process %d (SIGSEGV received).\n", getpid());
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
		} else exit(EXIT_SUCCESS);
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
		} else exit(EXIT_SUCCESS);
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
		} else exit(EXIT_SUCCESS);
	case SIGCHLD:
		logmsg(LOG_DEBUG, 1, "SIGCHILD received.\n");
		while ((pid = waitpid(-1, NULL, WNOHANG)) > 0) logmsg(LOG_DEBUG, 1, "Process %d terminated.\n", pid);

		/* reinstall original signal handler */
		if (signal(SIGCHLD, get_signal) == SIG_ERR)
			logmsg(LOG_ERR, 1, "Error - Unable to reinstall signal handler for SIGCHLD.\n");
		else logmsg(LOG_DEBUG, 1, "Signal handler for SIGCHLD reinstalled.\n");

		break;
	default:
		break;
	}
	return;
}


void install_signal_handlers(void) {
	/* create a pipe for process-internal signal delivery */
	if (pipe(sigpipe) == -1) {
		logmsg(LOG_ERR, 1, "Error - Unable to create signal pipe: %s.\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	DEBUG_FPRINTF(stdout, "  Signal pipe successfully created.\n");


	/* install signal handlers */
	if (signal(SIGHUP, get_signal) == SIG_ERR)
		fprintf(stdout, "  Warning - Handler for SIGHUP was not installed for %u.\n", getpid());
	else DEBUG_FPRINTF(stdout, "  Signal handler for SIGHUP installed.\n");
	
	if (signal(SIGSEGV, get_signal) == SIG_ERR)
		fprintf(stdout, "  Warning - Handler for SIGSEGV was not installed for %u.\n", getpid());
	else DEBUG_FPRINTF(stdout, "  Signal handler for SIGSEGV installed.\n");
	
	if (signal(SIGINT, get_signal) == SIG_ERR) 
		fprintf(stdout, "  Warning - Handler for SIGINT was not installed for %u.\n", getpid());
	else DEBUG_FPRINTF(stdout, "  Signal handler for SIGINT installed.\n");

	if (signal(SIGQUIT, get_signal) == SIG_ERR) 
		fprintf(stdout, "  Warning - Handler for SIGQUIT was not installed for %u.\n", getpid());
	else DEBUG_FPRINTF(stdout, "  Signal handler for SIGQUIT installed.\n");
	
	if (signal(SIGTERM, get_signal) == SIG_ERR)
		fprintf(stdout, "  Warning - Handler for SIGTERM was not installed for %u.\n", getpid());
	else DEBUG_FPRINTF(stdout, "  Signal handler for SIGTERM installed.\n");

	if (signal(SIGCHLD, get_signal) == SIG_ERR)
		fprintf(stdout, "  Warning - Handler for SIGCHLD was not installed for %u.\n", getpid());
	else DEBUG_FPRINTF(stdout, "  Signal handler for SIGCHLD installed.\n");

	return;
}


/* check_sigpipe() tries to read a signal from the process's signal pipe
 * if a signal is available, the signal handling routine is called.
 * select() on sigpipe[0] and call this function for safe signal handling */
int check_sigpipe(void) {
	int	sig, rv;

	if ((rv = read(sigpipe[0], &sig, sizeof(int))) == sizeof(int)) {
		/* caught a signal */
		logmsg(LOG_DEBUG, 1, "Process %d received signal %d on pipe.\n", getpid(), sig);
		handle_signal(sig);
	}
	if (rv == -1) {
		logmsg(LOG_ERR, 1, "Error - Unable to read signal from pipe: %s.\n", strerror(errno));
		return(-1);
	}
	return(0);
}
