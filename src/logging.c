/* logging.c
 * Copyright (C) 2005-2006 Tillmann Werner <tillmann.werner@gmx.de>
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
#include <stdarg.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>

#include "honeytrap.h"
#include "logging.h"


char *log_time(char ltime[20]) {
	time_t timeval;

	time(&timeval);
	strftime(ltime, 50, "%F %T", localtime(&timeval));
	return(ltime);
}


void logmsg(int level, int add_time, const char *format, ...) {
	char logline[LOGLINE_SIZE];
	va_list ap;
	int bytes_written, logline_size;
	
	if(level <= log_level) { 
		bzero(&logline, LOGLINE_SIZE);
		va_start(ap, format);
		if (add_time) {
			snprintf(logline, 24, "[%s]  ", log_time(ltime));
			if (log_level == LOG_DEBUG) sprintf(logline + strlen(logline), "%5d  ", getpid());
		}
		vsprintf(logline + strlen(logline), format, ap);
		logline_size = strlen(logline);

		if ((bytes_written = write(logfile_fd, logline, logline_size)) != logline_size)
			perror("Error while writing into honeytrap logfile");

		/* log to stdout as well if we are not running as daemon */
		if ((STDOUT_FILENO != logfile_fd) && (daemonize != 1) &&
			((bytes_written = write(STDOUT_FILENO, logline, logline_size)) != logline_size))
			perror("Error while logging to stdout");
		va_end(ap);
	}
	return;
}
