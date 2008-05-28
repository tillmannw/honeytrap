/* hex2bin.c
 * Copyright (C) 2006-2008 Tillmann Werner <tillmann.werner@gmx.de>
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
 * hex2bin reads input in hexadecimal notion from a file, converts it into
 * binary data and writes it to stdout. This is useful for converting
 * exploit code or malware binaries that are submitted in hex.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
	char option;
	u_char buf[4];
	unsigned int chr[2];
	int swap, retval;
	FILE *file;

	swap = 0;

	// process args
	while((option = getopt(argc, argv, "sh?")) > 0) {
		switch(option) {
			case 's':
				swap = 1;
				break;
			case 'h':
			case '?':
			default:
				printf("Usage: %s [-s] file   (-s swaps byte order)\n", argv[0]);
				exit(EXIT_SUCCESS);
		}
	}

	// open file
	if (argc - optind < 1) {
		fprintf(stderr, "Error - No filename given.\n");
		exit(EXIT_FAILURE);
	}
	if ((file = fopen(argv[optind++], "r")) == NULL) {
		fprintf(stderr, "Error - Unable to open file: %s.\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	// process data
	errno = 0;
	for (;;) switch ((retval = fread(&buf, 2, 2, file))) {
	case 0:
		fclose(file);
		if ((retval = EOF) && errno) {
			fprintf(stderr, "Error - Unable to read from file: %s.\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
		exit(EXIT_SUCCESS);
	case 1:
		sscanf((char *) buf, "%2x", &chr[0]);
		fprintf(stdout, "%c", chr[0]);
		break;
	case 2:
		sscanf((char *) buf, "%2x%2x", &chr[0], &chr[1]);
		fprintf(stdout, "%c%c", swap ? chr[1] : chr[0], swap ? chr[0] : chr[1]);
		break;
	}

	exit(EXIT_SUCCESS); // never reached
}
