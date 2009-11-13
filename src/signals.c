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
#include <execinfo.h>
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

#define MASTER_PROCESS (pid = getpid()) == master_pid


void get_signal(int sig) {
	if (signal(sig, SIG_IGN) == SIG_IGN) return;
	if (write(sigpipe[1], (char *) &sig, sizeof(int)) == -1) {
		if (write(logfile_fd, "Error - Unable to write signal to pipe.\n", 40)) { };
		if ((STDOUT_FILENO != logfile_fd) && (daemonize != 1))
			if (write(STDOUT_FILENO, "Error - Unable to write signal to pipe.\n", 40)) { };
		exit(EXIT_FAILURE);
	}
	return;
}


void handle_termsig(int sig) {
	int			nptrs;
	pid_t			pid;
	struct sigaction	s_action;
	void			*buffer[BUFSIZ];

	sigemptyset(&s_action.sa_mask);
	s_action.sa_flags	= 0;
	s_action.sa_handler	= SIG_IGN;

	switch (sig) {
	case SIGSEGV:
	case SIGILL:
#ifdef HAVE_SIGBUS
	case SIGBUS:
#endif
		logmsg(LOG_ERR, 1, "Error - Terminating signal (%d) received by process %u.\n", sig, getpid());

		logmsg(LOG_ERR, 1, "-- Begin process backtrace --\n");
		nptrs = backtrace(buffer, BUFSIZ);
		backtrace_symbols_fd(buffer, nptrs, logfile_fd);
		logmsg(LOG_ERR, 1, "-- End of process backtrace --\n");

		break;
	default:
		logmsg(LOG_DEBUG, 1, "Terminating signal (%d) received.\n", sig);
	}
	if (MASTER_PROCESS) {
		if (kill(0-getpgrp(), SIGINT) == 0) {
			logmsg(LOG_DEBUG, 1, "Signal was successfully forwarded to process group.\n");
			/* wait for children */
			while ((pid = waitpid(-master_pid, 0, WNOHANG)) > 0) logmsg(LOG_DEBUG, 1, "Process %d terminated.\n", pid);
			if (pid == -1 && errno != ECHILD) {
				logmsg(LOG_ERR, 1, "Error - Unable to wait for process status changes: %m.\n");
				exit(EXIT_FAILURE);
			}
		} else {
			logmsg(LOG_ERR, 1, "Error - Unable to forward signal to process group: %m.\n");
			clean_exit(EXIT_FAILURE);
		}
		clean_exit(EXIT_SUCCESS);
	} else exit(EXIT_SUCCESS);

	/* suicide... */
	if (kill(master_pid, sig) < 0) logmsg(LOG_ERR, 1, "Error - Unable to terminate master process: %m.\n");
	return;
}


void handle_sighup(int sig) {
	pid_t			pid;
	struct sigaction	s_action;

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
	memset(&s_action, 0, sizeof(struct sigaction));
	s_action.sa_handler	= get_signal;
#ifdef SA_RESTART
	s_action.sa_flags	|= SA_RESTART;
#endif
	if (sigaction(SIGHUP, &s_action, NULL) == -1) {
		logmsg(LOG_ERR, 1, "Error - Unable to reinstall signal handler for SIGHUP.\n");
		exit(EXIT_FAILURE);
	} else logmsg(LOG_DEBUG, 1, "Signal handler for SIGHUP reinstalled.\n");

	return;
}


void handle_sigchld(int sig) {
	pid_t			pid;
	int			status;
	struct sigaction	s_action;

	logmsg(LOG_DEBUG, 1, "SIGCHILD received.\n");
	status = 0;
	while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
		logmsg(LOG_DEBUG, 1, "Process %d terminated.\n", pid);
		if WIFSIGNALED(status)
			logmsg(LOG_WARN, 1, "Warning - Process %d was terminated by signal %d.\n", pid, WTERMSIG(status));
		else if (WIFEXITED(status) && (WEXITSTATUS(status) == EXIT_FAILURE))
			logmsg(LOG_WARN, 1, "Warning - Process %d exited on failure.\n", pid);
		status = 0;
	}
	if (pid == -1 && errno != ECHILD) {
		logmsg(LOG_ERR, 1, "Error - Unable to wait for process status changes: %m.\n");
		exit(EXIT_FAILURE);
	}

	/* reinstall original signal handler */
	memset(&s_action, 0, sizeof(struct sigaction));
	s_action.sa_handler	= get_signal;
#ifdef SA_RESTART
	s_action.sa_flags	|= SA_RESTART;
#endif
	if (sigaction(SIGCHLD, &s_action, NULL) == -1) {
		logmsg(LOG_ERR, 1, "Error - Unable to reinstall signal handler for SIGCHLD.\n");
		exit(EXIT_FAILURE);
	} else logmsg(LOG_DEBUG, 1, "Signal handler for SIGCHLD reinstalled.\n");

	return;
}


void install_signal_handlers(void) {
	u_char			i;
	struct sigaction	s_action;
	static int		sigs[] = {
		SIGCHLD,
#ifdef HAVE_SIGBUS
		SIGBUS,
#endif
		SIGHUP,
		SIGILL,
		SIGINT,
		SIGQUIT,
		SIGSEGV,
		SIGTERM
	};

	create_sigpipe();
	
	/* install signal handlers */
	memset(&s_action, 0, sizeof(struct sigaction));
	s_action.sa_handler	= get_signal;
#ifdef SA_RESTART
	s_action.sa_flags	|= SA_RESTART;
#endif
	for (i = 0; i < sizeof(sigs)/sizeof(sigs[0]); i++) {
		if (sigaction(sigs[i], &s_action, NULL) == -1) {
			fprintf(stdout, "  Error - Handler for signal %d was not installed for %u: %m.\n", sigs[i], getpid());
			exit(EXIT_FAILURE);
		} else DEBUG_FPRINTF(stdout, "  Handler for signal %d installed.\n", sigs[i]);
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
		fprintf(stderr, "  Error - Unable to create signal pipe: %m.\n");
		exit(EXIT_FAILURE);
	}

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
		switch (sig) {
		case SIGCHLD:
			handle_sigchld(sig);
			break;
		case SIGHUP:
			handle_sighup(sig);
			break;
#ifdef HAVE_SIGBUS
		case SIGBUS:
#endif
		case SIGILL:
		case SIGINT:
		case SIGQUIT:
		case SIGSEGV:
		case SIGTERM:
			handle_termsig(sig);
			break;
		default:
			break;
		}
		break;
	case 0:
		logmsg(LOG_WARN, 1, "Warning - Signal pipe ready to read but not enough data available.\n");
		return(0);
	case -1:
		logmsg(LOG_ERR, 1, "Error - Unable to read signal from pipe: %m.\n");
		return(-1);
	}
	return(0);
}


int sleep_sigaware(struct timeval *tv) {
	fd_set 	rfds;

	FD_ZERO(&rfds);
	FD_SET(sigpipe[0], &rfds);

	for (;;) {
		switch (select(sigpipe[0]+1, &rfds, NULL, NULL, tv)) {
		case -1:
			if (errno == EINTR) {
				if (check_sigpipe() == -1) exit(EXIT_FAILURE);
				break;
			}
			logmsg(LOG_DEBUG, 1, "Error in signal-aware sleep - select() failed: %s.\n", strerror(errno));
			return -1;
		case 0:
			return 0;
		default:
			if (FD_ISSET(sigpipe[0], &rfds) && (check_sigpipe() == -1)) exit(EXIT_FAILURE);
		}
	}
}
