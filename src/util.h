/* util.h
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

#ifndef __HONEYTRAP_UTIL_H
#define __HONEYTRAP_UTIL_H 1

#define MAX_LINE 1024
#define READ_SIZE 1440

struct strtk {
	char *string;
	int offset;
};

int valid_ipaddr(uint32_t address);
int read_line(int socket, char *line, int timeout);
struct strtk extract_token(char *parse_string);

#endif
