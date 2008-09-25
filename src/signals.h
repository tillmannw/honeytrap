/* signals.h
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

#ifndef __HONEYTRAP_SIGNALS_H
#define __HONEYTRAP_SIGNALS_H 1

#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/wait.h>
#include <sys/types.h>

int sigpipe[2];

pid_t master_pid;

void get_signal(int sig);
void handle_sigchld(int sig);
void handle_sighup(int sig);
void handle_termsig(int sig);
void install_signal_handlers(void);
void create_sigpipe(void);
int check_sigpipe(void);
int sleep_sigaware(struct timeval *tv);

#endif
