/* edist.c
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
 * edist calculates the edit distance (aka levenshtein distance) for two
 * arbitrary (text or binary) files and tells the percentage of similarity
 * and the absolute value. The algorithm variant used here uses linear space.
 *
 * The edit distance can be used as a metric for binary file comparison.
 * Further information can be found on
 * <http://en.wikipedia.org/wiki/Levenshtein_distance>.
 * 
 * Use gcc and compile with   -O -fforce-mem -frerun-loop-opti
 * to improve performace.
 */

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <string.h>

#define COST_INS	1
#define COST_DEL	1
#define COST_REP	1
#define min(a, b) ((a) < (b) ? a : b)
#define max(a, b) ((a) > (b) ? a : b)


struct bstr {
	u_char *str;
	u_int32_t len;
};


/* load data into memory
 * faster than mmap() at least on Linux */
struct bstr file2string(const char *filename) {
	int bytes_read, fd;
	u_char buffer[BUFSIZ];
	struct bstr bstring;

	bstring.len	= 0;
	bstring.str	= NULL;
	
	if ((fd = open(filename, 0)) == -1) {
		fprintf(stderr, "Unable to open %s: %s.\n", filename, strerror(errno));
		exit(1);
	}
	while ((bytes_read = read(fd, buffer, BUFSIZ)) > 0) {
		if ((bstring.str = (void *) realloc(bstring.str, bstring.len + bytes_read)) == NULL) {
			fprintf(stderr, "Unable to allocate memory: %s.\n", strerror(errno));
			exit(1);
		}
		memcpy(bstring.str + bstring.len, buffer, bytes_read);
		bstring.len += bytes_read;
	}
	if (bytes_read < 0) {
		fprintf(stderr, "Unable to read from %s: %s.\n", filename, strerror(errno));
		exit(1);
	}
	close(fd);
	return(bstring);
}


/* calculate and return edit distance */
u_int32_t edit_dist(struct bstr str1, struct bstr str2) {
	register u_int32_t i, j;
	u_int32_t *p, *q, *r;

	if ((p = (uint *) calloc(str2.len, sizeof(uint))) == NULL) {
		fprintf(stderr, "Unable to allocate memory: %s.\n", strerror(errno));
		exit(1);
	}
	if ((q = (uint *) calloc(str2.len, sizeof(uint))) == NULL) {
		fprintf(stderr, "Unable to allocate memory: %s.\n", strerror(errno));
		exit(1);
	}

	p[0] = 0;
	for(j=1; j<=str2.len; ++j) p[j] = p[j-1] + COST_INS;

	for(i=1; i<=str1.len; ++i) {
		q[0] = p[0] + COST_DEL;
		for(j=1; j<=str2.len; ++j)
			q[j] = min(min(p[j]+COST_DEL, q[j-1]+COST_INS),
				p[j-1]+(str1.str[i-1] == str2.str[j-1] ? 0 : COST_REP));

		r = p;
		p = q;
		q = r;
	}
	return(p[str2.len]);
}


/* calculate similarity of binary files (in percent) via edit distance */
int main(int argc, char *argv[]) {
	struct bstr bstr1, bstr2;
	u_int32_t dist;
	double eq, ed;

	if (argc < 3) printf("usage: %s file1 file2\n", argv[0]);
	else {
		bstr1	= file2string(argv[1]);
		bstr2	= file2string(argv[2]);

		// special cases: at least one input is empty
		if (!bstr1.len && !bstr2.len) { 
			printf("Similarity: 100%% (edit distance: 0).\n");
			return(EXIT_SUCCESS);
		}
		if (!bstr1.len || !bstr2.len) { 
			printf("Similarity: 0%% (edit distance: %u).\n", abs(bstr1.len-bstr2.len));
			return(EXIT_SUCCESS);
		}

		dist	= edit_dist(bstr1, bstr2);

		ed	= edit_dist(bstr1, bstr2) - abs(bstr1.len-bstr2.len);
		eq	= bstr1.len + bstr2.len - abs(bstr1.len-bstr2.len);
		eq	= 1 - (ed / eq);

		printf("Similarity: %.2f%% (edit distance: %u).\n", eq, dist);
	}
	return(EXIT_SUCCESS);
}
