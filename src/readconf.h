/* readconf.h
 * Copyright (C) 2006 Tillmann Werner <tillmann.werner@gmx.de>
 *
 * This file is free software; as a special exception the author gives
 * unlimited permission to copy and/or distribute it, with or without
 * modifications, as long as this notice is preserved.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
 * implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */

#ifndef __HONEYTRAP_READCONF_H
#define __HONEYTRAP_READCONF_H 1

#include <netdb.h>

char *user, *group;

void *get_value(char *buf, const char delim);
int configure(int argc, char *argv[]);
int parse_config_file(const char *filename);
int process_config_option(char *opt, char* val, const int line_number, const char *filename);

#endif
