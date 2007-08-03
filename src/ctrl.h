/* ctrl.h
 * Copyright (C) 2006-2007 Tillmann Werner <tillmann.werner@gmx.de>
 *
 * This file is free software; as a special exception the author gives
 * unlimited permission to copy and/or distribute it, with or without
 * modifications, as long as this notice is preserved.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
 * implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */

#ifndef __HONEYTRAP_CTRL_H
#define __HONEYTRAP_CTRL_H 1

void usage(char *progname);
void clean_exit(int status);
int do_daemonize(void);
int create_pid_file(void);
pid_t myfork(void);

#endif
