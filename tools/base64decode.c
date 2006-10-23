/* base64decode.c
 * Copyright (C) 2006 Tillmann Werner <tillmann.werner@gmx.de>
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
 * base64decode maps a file into memory, scans it for characteristic
 * strings and tries to base64-decode parts of it.
 *
 * The decoded message is printed to stdout.
 * 
 * Use gcc and compile with   -O -fforce-mem -frerun-loop-opti
 * to improve performace.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <strings.h>

struct dec {
	char *str;
	u_int32_t len;
};

struct dec decode(const char* code, int len) {
	u_char ch, inbuf[3], outbuf[4];
	u_int32_t charctr, bufctr, ign, eot, i;
	struct dec ret;

	eot	= 0;
	ign	= 0;
	bufctr	= 0;
	ret.len	= 0;

	ret.str  = (u_char*) malloc(len*3/4+1);
	bzero(ret.str, len*3/4+1);

	for (i=0; i<len; i++) {
		ch = code[i];

		if isupper(ch) ch -= 'A';
		else if islower(ch) ch = ch - 'a' + 26;
		else if isdigit(ch) ch = ch - '0' + 52;
		else if (ch == '+') ch = 62;
		else if (ch == '=') eot = 1;
		else if (ch == '/') ch = 63;
		else ign = 1;

		if (!ign) {
			if (eot) {
				if (bufctr == 0) return;
				charctr = ((bufctr == 1) || (bufctr == 2)) ? 1 : 2;
				bufctr = 3;
			} else charctr = 3;

			inbuf[bufctr++] = ch;

			if (bufctr == 4) {
				bufctr = 0;

				ret.str[ret.len++] =  (inbuf[0] << 2) | ((inbuf[1] & 0x30) >> 4);
				if (charctr > 0) ret.str[ret.len++] =  ((inbuf[1] & 0x0F) << 4) | ((inbuf[2] & 0x3C) >> 2);
				if (charctr > 1) ret.str[ret.len++] =  ((inbuf[2] & 0x03) << 6) | (inbuf[3] & 0x3F);
			}
			if (eot) return(ret);
		}
	}
	return(ret);
}

int main(int argc, char *argv[]) {
	int fd, bytes_read, i;
	struct stat filestat;
	u_char *content, *code, v, in[4], out[3];
	struct dec decoded;

	if (argc < 2) {
		fprintf(stderr, "Error - No filename given.\n");
		exit(1);
	}

	/* open file */
	if ((fd = open(argv[1], O_RDONLY)) == -1) {
		fprintf(stderr, "Error - Unable to open file: %s.\n", strerror(errno));
		exit(1);
	}

	/* get file size */
	if (fstat(fd, &filestat) != 0) {
		fprintf(stderr, "Error - Unable to get file size: %s.\n", strerror(errno));
		exit(1);
	}
	if (filestat.st_size < 1) {
		fprintf(stdout, "File is empty.\n");
		exit(0);
	}

	/* map file content into memory */
	if ((content = (u_char *) malloc(filestat.st_size)) == NULL) {
		fprintf(stderr, "Error - Unable to allocate memory: %s.\n", strerror(errno));
		exit(1);
	}
	bzero(content, filestat.st_size);
	bytes_read = 0;
	if ((bytes_read = read(fd, content+bytes_read, filestat.st_size)) < filestat.st_size) {
		if (bytes_read  == -1) {
			fprintf(stderr, "Error - Unable to map file into memory: %s.\n", strerror(errno));
			exit(1);
		}
		if (bytes_read == 0) {
			fprintf(stderr, "Error - EOF reached too early.\n");
			exit(1);
		}
	}
	close(fd);

	/* look for 'Negotiate ' in content, base64 code starts after it */
	/* checks for other characteristic strings can be done here as well */
	if ((code = strstr(content, "Negotiate "))) code += 10;
	else code = content;

	/* decode base64 code */
	decoded = decode((char *)code, bytes_read);

	/* print it to stdout */
	for (i=0; i<decoded.len; fprintf(stdout, "%c", decoded.str[i++]));

	free(decoded.str);
	free(content);
}
