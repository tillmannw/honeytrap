/* ctrl.c
 * Copyright (C) 2006-2015 Tillmann Werner <tillmann.werner@gmx.de>
 *
 * This file is free software; as a special exception the author gives
 * unlimited permission to copy and/or distribute it, with or without
 * modifications, as long as this notice is preserved.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
 * implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "ctrl.h"
#include "honeytrap.h"
#include "logging.h"
#include "nfqmon.h"
#include "pcapmon.h"
#include "plugin.h"
#include "response.h"
#include "signals.h"

void usage(char *progname) {
#ifndef USE_PCAP_MON
	fprintf(stdout, "Usage: %s [ -Dmv ] [ -l seconds ] [ -r seconds ] [ -t log level ]\n\t\t[ -u user ] [ -g group ]\n", progname);
#else
	fprintf(stdout, "Usage: %s [ -Dpmv ] [ -i interface ] [ -a ip address ] [ -l seconds ]\n\t\t[ -r seconds ] [ -t log level ] [ -u user ] [ -g group ]\n", progname);
	fprintf(stdout, "\t-a:\tip address or hostname (normally not needed)\n");
#endif
	fprintf(stdout, "\t-g:\tgroup\n");
	fprintf(stdout, "\t-h:\tthis output\n");
#ifdef USE_PCAP_MON
	fprintf(stdout, "\t-i:\tinterface, defaults to first usable device\n");
#endif
	fprintf(stdout, "\t-l:\tlisten timeout (sec), default is 1\n");
	fprintf(stdout, "\t-m:\tenable mirror mode\n");
#ifdef USE_PCAP_MON
	fprintf(stdout, "\t-p:\tenable promiscuous mode\n");
#endif
	fprintf(stdout, "\t-r:\tread timeout (sec), default is 30\n");
	fprintf(stdout, "\t-t:\tlog level (0-6), default is 3 (LOG_NOTICE)\n");
	fprintf(stdout, "\t-u:\tuser\n");
	fprintf(stdout, "\t-v:\tprint version number\n");
	fprintf(stdout, "\t-C:\tconfiguration file\n");
	fprintf(stdout, "\t-D:\tdon't daemonize\n");
	fprintf(stdout, "\t-L:\tlogfile\n");
	fprintf(stdout, "\t-P:\tpid file\n");
	exit(EXIT_SUCCESS);
}


void clean_exit(int status) {
#ifdef USE_PCAP_MON
	// free bpf filter string
	logmsg(LOG_DEBUG, 1, "Freeing BPF filter string.\n");
	free(bpf_filter_string);
#endif
#ifdef USE_NFQ_MON
	// unhook from netfilter-queue
	if (h) {
		logmsg(LOG_DEBUG, 1, "Destroying NFQ handle.\n");
		if (qh && nfq_destroy_queue(qh) != 0) {
			logmsg(LOG_ERR, 1, "Error - Could not destroy NFQ handle: %m.\n");
		}

		logmsg(LOG_DEBUG, 1, "Unhooking NFQ connection monitor.\n");
		if (nfq_close(h) != 0) {
			logmsg(LOG_ERR, 1, "Error - Could not close NFQ connection monitor: %m.\n");
		}
	}
#endif

	logmsg(LOG_DEBUG, 1, "Unloading default responses.\n");
	unload_default_responses();

	/* unloading plugins */
	logmsg(LOG_DEBUG, 1, "Unloading plugins.\n");
	unload_plugins();

	if (pidfile_fd >= 0) {
		logmsg(LOG_DEBUG, 1, "Unlocking pid file.\n");
		if (lockf(pidfile_fd, F_ULOCK, 0) < 0) 
			logmsg(LOG_ERR, 1, "Error - Unable to unlock pid file: %m.\n");

		logmsg(LOG_DEBUG, 1, "Closing pid file.\n");
		if (close(pidfile_fd) == -1)
			logmsg(LOG_ERR, 1, "Error - Unable to close pid file: %m.\n");

		logmsg(LOG_DEBUG, 1, "Removing pid file.\n");
		if (unlink(pidfile_name) == -1)
			logmsg(LOG_ERR, 1, "Error - Unable to remove pid file: %m.\n");
	} else logmsg(LOG_DEBUG, 1, "No pid file installed.\n");

	logmsg(LOG_NOTICE, 1, "---- honeytrap stopped ----\n");
	
	if (close(logfile_fd) == -1) logmsg(LOG_ERR, 1, "Error - Unable to close logfile: %m.\n");

	exit(status);
}


/* switch to daemon environment and fork */
int do_daemonize(void) {
	int i, fd0, fd1, fd2;
	pid_t pid;
	struct rlimit rl;

	if (logfile_fd == STDOUT_FILENO) {
		fprintf(stderr, "  Error - Logging to stdout is not possible while running in daemon mode.\n");
		clean_exit(EXIT_SUCCESS);
	}

	DEBUG_FPRINTF(stdout, "  Setting up daemon environment.\n");

	umask(0);

	if (getrlimit(RLIMIT_NOFILE, &rl) < 0) {
		fprintf(stderr, "  Error - Unable to daemonize: %m.\n");
		exit(EXIT_FAILURE);
	}

	/* become session leader and loose controlling TTY */
	if ((pid = myfork()) < 0) {
		fprintf(stderr, "  Error - Unable to daemonize: %m.\n");
		exit(EXIT_FAILURE);
	} else if (pid != 0) exit(EXIT_SUCCESS);
		
	setsid();
		
	/* fork again, future opens must not allocate controlling TTYs */
	if ((pid = myfork()) < 0) {
		fprintf(stderr, "  Error - Unable to daemonize: %m.\n");
		exit(EXIT_FAILURE);
	} else if (pid != 0) {
		DEBUG_FPRINTF(stdout, "  Successfully changed into daemon environment.\n");
		fprintf(stdout, "\nhoneytrap v%s %s\n", VERSION, COPYRIGHT_STRING);
		fflush(NULL);
		exit(EXIT_SUCCESS);
	}


	/* change working directory to root directory */
	DEBUG_FPRINTF(stdout, "  Current working directory is %s, changing it to /.\n", old_cwd);
	if (chdir("/") < 0) {
		fprintf(stderr, "  Error - Cannot change working directory: %m.\n");
		exit(EXIT_FAILURE);
	}


	/* close open file descriptors, only keep logfile and signal pipe */
	if (rl.rlim_max == RLIM_INFINITY) rl.rlim_max = 1024;
	for (i=0; i < rl.rlim_max; i++)
		if ((i != logfile_fd) && (i != sigpipe[0]) && (i != sigpipe[1]) && (close(i) == -1))
			fprintf(stdout, "  Warnging - Could not close file descriptor %d: %m.\n", i);

	/* attach file descriptors 0, 1 and 2 to /dev/null to prevent accidentally standard IO */
	if ((fd0 = open("/dev/null", O_RDWR)) == -1) {
		fprintf(stderr, "  Error - Unable to set stdin to /dev/null: %m.\n");
		exit(EXIT_FAILURE);
	}
	if ((fd1 = dup(fd0)) == -1) {
		fprintf(stderr, "  Error - Unable to set stdout to /dev/null: %m.\n");
		exit(EXIT_FAILURE);
	}
	if ((fd2 = dup(fd0)) == -1) {
		fprintf(stderr, "  Error - Unable to set stderr to /dev/null: %m.\n");
		exit(EXIT_FAILURE);
	}
	fflush(NULL);

	return(1);
}


/* write master process id to pid file */
int create_pid_file(void) {
	char pid_str[6];

	if ((pidfile_fd = open(pidfile_name, O_EXCL | O_CREAT | O_NOCTTY | O_RDWR, 0640)) == -1) {
		logmsg(LOG_ERR, 1, "Error - Unable to open pid file: %m.\n");
		exit(EXIT_SUCCESS);
	}
	if (lockf(pidfile_fd, F_TLOCK, 0) < 0) {
		logmsg(LOG_ERR, 1, "Error - Unable to lock pid file: %m.\n");
		clean_exit(EXIT_SUCCESS);
	}

	master_pid = getpid();

	bzero(pid_str, 6);
	snprintf(pid_str, 6,"%d", master_pid);
	if (write(pidfile_fd, pid_str, strlen(pid_str)) != strlen(pid_str)) {
		logmsg(LOG_ERR, 1, "Error - Unable to write pid file: %m.\n");
		return(0);
	}
	logmsg(LOG_DEBUG, 1, "Master process pid written to %s.\n", pidfile_name);

	return(1);
}


pid_t myfork(void) {
	pid_t pid;

	/* reopen signal pipe in child process */
	if ((pid = fork()) == 0) create_sigpipe();
	return(pid);
}
