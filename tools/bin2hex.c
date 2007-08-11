/* bin2hex.c
 * Copyright (C) 2007 Tillmann Werner <tillmann.werner@gmx.de>
 *
 * This file is free software; as a special exception the author gives
 * unlimited permission to copy and/or distribute it, with or without
 * modifications, as long as this notice is preserved.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
 * implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 *
 * This file is part of the honeytrap tools collection.
 * 
 * bin2hex reads a file bytewise and write its hex values to stdout. 
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

int main(int argc, char *argv[]) {
	u_char byte;
	int retval;
	FILE *file;

	if (argc < 2) {
		fprintf(stderr, "Error - No filename given.\n");
		exit(1);
	}

	/* open file */
	if ((file = fopen(argv[1], "r")) == NULL) {
		fprintf(stderr, "Error - Unable to open file: %s.\n", strerror(errno));
		exit(1);
	}

	errno = 0;
	while((retval = fscanf(file, "%c", &byte)) > 0) fprintf(stdout, "\\x%02x", byte);
	if ((retval = EOF) && errno) fprintf(stderr, "Error - Unable to read from file: %s.\n", strerror(errno));

	fclose(file);
	return(0);
}
