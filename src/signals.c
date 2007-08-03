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
#ifdef HAVE_SIGBUS
	case SIGBUS:
#endif
	case SIGCHLD:
	case SIGHUP:
	case SIGILL:
	case SIGINT:
	case SIGQUIT:
	case SIGSEGV:
	case SIGTERM:
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
	pid_t	pid;
	int	status;

	switch(sig) {
#ifdef HAVE_SIGBUS
	case SIGBUS:
#endif
	case SIGILL:
	case SIGSEGV:
		if (current_plugfunc)
			logmsg(LOG_ERR, 1, "Error - Signal %d received in process %d, %s::%s().\n",
				sig, getpid(), current_plugfunc->plugnam, current_plugfunc->funcnam);
		else 
			logmsg(LOG_ERR, 1, "Error - Signal %d received in process %d.\n", sig, getpid());
		_exit(EXIT_FAILURE);
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
		for (;;) {
			status = 0;
			if ((pid = waitpid(-1, &status, WNOHANG)) > 0)
				logmsg(LOG_DEBUG, 1, "Process %d terminated.\n", pid);
				if WIFSIGNALED(status)
					logmsg(LOG_WARN, 1, "Warning - Process %d was terminated by signal %d.\n", pid, WTERMSIG(status));
				else if (WIFEXITED(status) && (WEXITSTATUS(status) == EXIT_FAILURE))
					logmsg(LOG_WARN, 1, "Warning - Process %d exited on failure.n", pid);
			else break;
		}

		/* reinstall original signal handler */
		if (signal(SIGCHLD, get_signal) == SIG_ERR)
			logmsg(LOG_ERR, 1, "Error - Unable to reinstall signal handler for SIGCHLD.\n");
		else logmsg(LOG_DEBUG, 1, "Signal handler for SIGCHLD reinstalled.\n");

		break;
	default:
		logmsg(LOG_WARN, 1, "Warning - Don't know how to handle signal %d in process %d.\n", sig, getpid());
		break;
	}
	return;
}


void install_signal_handlers(void) {
	u_char	i;
	static int sigs[] = {
#ifdef HAVE_SIGBUS
		SIGBUS,
#endif
		SIGCHLD,
		SIGHUP,
		SIGILL,
		SIGINT,
		SIGQUIT,
		SIGSEGV,
		SIGTERM
	};

	create_sigpipe();
	
	/* install signal handlers */
	for (i = 0; i < sizeof(sigs)/sizeof(sigs[0]); i++) {
		if (signal(sigs[i], get_signal) == SIG_ERR)
			fprintf(stdout, "  Warning - Handler for signal %d was not installed for %u.\n", i, getpid());
		else DEBUG_FPRINTF(stdout, "  Handler for signal %d installed.\n", i);
	}
	return;
}


void create_sigpipe(void) {
	/* create a pipe for process-internal signal delivery
	 * this function must be called in every process, e.g. after a fork() 
	 * as pipes are inherited by childs which would break signal delivery */

	/* make sure there are no open pipe endpoints */
	close(sigpipe[0]);
	close(sigpipe[1]);

	/* (re)open pipe */
	if (pipe(sigpipe) == -1) {
		fprintf(stderr, "  Error - Unable to create signal pipe: %s.\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	DEBUG_FPRINTF(stdout, "  Signal pipe successfully created for process %d.\n", getpid());

	return;
}


/* check_sigpipe() tries to read a signal from the process's signal pipe
 * if a signal is available, the signal handling routine is called.
 * select() on sigpipe[0] and call this function for safe signal handling */
int check_sigpipe(void) {
	int	sig, rv;

	switch(rv = read(sigpipe[0], &sig, sizeof(int))) {
	case sizeof(int):
		/* caught a signal */
		logmsg(LOG_DEBUG, 1, "Process %d received signal %d on pipe.\n", getpid(), sig);
		handle_signal(sig);
		break;
	case 0:
		logmsg(LOG_WARN, 1, "Warning - Signal pipe ready to read but not enough data available.\n");
		return(0);
	case -1:
		logmsg(LOG_ERR, 1, "Error - Unable to read signal from pipe: %s.\n", strerror(errno));
		return(-1);
	}
	return(0);
}
