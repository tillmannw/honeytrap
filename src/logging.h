/* logging.h
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

#ifndef __HONEYTRAP_LOGGING_H
#define __HONEYTRAP_LOGGING_H 1

#include <time.h>
#include <fcntl.h>
#include <sys/types.h>

typedef enum {
	LL_OFF		= 0,
	LL_ERR		= 1,
	LL_WARN		= 2,
	LL_NOTICE	= 3,
	LL_INFO		= 4,
	LL_NOISY	= 5,
	LL_DEBUG	= 6,
} s_log_level;

s_log_level log_level;

#define	LOG_OFF		0
#define LOG_ERR		1
#define LOG_WARN	2
#define LOG_NOTICE	3	// default
#define LOG_INFO	4
#define LOG_NOISY	5
#define LOG_DEBUG	6

/*
u_char log_level;
*/

#define LOGLINE_SIZE	4069	/* truncates longer lines */

#define DEBUG_FPRINTF	if (log_level == LOG_DEBUG) fprintf

int	logfile_fd;
char	portstr[16];

void logmsg(int level, int add_time, const char * format, ...) __attribute__ ((format (printf, 3, 4)));

#endif
