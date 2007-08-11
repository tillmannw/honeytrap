/* ngtrie.c
 * Copyright (C) 2007 Tillmann Werner <tillmann.werner@gmx.de>
 *                    Till Breuer <till.breuer@gmx.de>
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
 * ngtrie calculates the similarity between two input files
 * using n-grams stored in a trie.
 *
 * The similarity in percent is printed to stdout.
 */

#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

struct trie_node;
typedef struct trie_node *trie;

typedef struct trie_node {
	u_char key;
	u_int32_t freq1;
	u_int32_t freq2;
	trie next;
	trie childlist;
} trie_node;


double sqrnorm1, sqrnorm2, dotprod;


trie new_trie_node(void) {
	trie t;

	if ((t = malloc(sizeof(trie_node))) != NULL)
		memset(t, 0, sizeof(trie_node));

	return(t);
}


/* inserts an ngram into the trie or update its frequency */
void ngram_ins(trie t, const u_char *data, ssize_t n, u_char snum) {
	ssize_t k;
	u_char curchar;

	if (t == NULL) {
		fprintf(stderr, "Error - Cannot insert into empty trie.\n");
		exit(EXIT_FAILURE);
	}

	for (k=0; k<n; k++) {
		curchar = data[k];

		/*
		if (t && t->freq1 == 0 && t->freq2 == 0) {
			// both frequencies are zero, thus we're at the root node
			// just set pointer to child list
			t = t->childlist;
		}
		*/

		if (t->childlist == NULL) {
			/* need to create a first child */
			if ((t->childlist = new_trie_node()) == NULL) {
				fprintf(stderr, "Error - Unable to create new trie node: %s.\n", strerror(errno));
				exit(EXIT_FAILURE);
			} 
			t = t->childlist;
			t->key = curchar;
		} else {
			/* search for key in child list */
			t = t->childlist;
			if (t->key != curchar) {
				while ((t->next) && (t->key) && (t->key != curchar)) t = t->next;
				/* key not present, create new node */
				if (t->key != curchar) {
					if ((t->next = new_trie_node()) == NULL) {
						fprintf(stderr, "Error - Unable to create new trie node: %s.\n", strerror(errno));
						exit(EXIT_FAILURE);
					} 
					t = t->next;
					t->key = curchar;
				}
			}
		}

		/* we're always at the right node here, update frequency */
		(snum == 0) ? t->freq1++ : t->freq2++;
	}
	return;
}


/* calculates needed values and free processed trie nodes */
void calc_and_del_trie(trie t) {
	if (t) {
		if (t->childlist) calc_and_del_trie(t->childlist);
		else {
			/* it's a leaf node, update result */
			sqrnorm1 += pow(t->freq1, 2);
			sqrnorm2 += pow(t->freq2, 2);
			dotprod += t->freq1 * t->freq2;
		}

		if (t->next) calc_and_del_trie(t->next);
	
		free(t);
	}
	return;
}


/* builds a trie of ngrams */
trie build_ngram_trie(int n, const u_char *data1, const u_char *data2, ssize_t len1, ssize_t len2) {
	trie ngtrie = NULL;
	ssize_t pos = 0;

	if ((ngtrie = new_trie_node()) == NULL) {
		fprintf(stderr, "Error - Unable to initialize trie: %s.\n", strerror(errno));
		exit(EXIT_FAILURE);
	} 

	/* process data strings */
	if (len1 < len2) {
		for (pos=0; pos < len1-n+1; pos++) ngram_ins(ngtrie, &data1[pos], n, 0);
		for (pos=0; pos < len2-n+1; pos++) ngram_ins(ngtrie, &data2[pos], n, 1);
	} else {
		for (pos=0; pos < len2-n+1; pos++) ngram_ins(ngtrie, &data2[pos], n, 0);
		for (pos=0; pos < len1-n+1; pos++) ngram_ins(ngtrie, &data1[pos], n, 1);
	}

	return(ngtrie);
}


int main(int argc, char *argv[]) {
	int fd, bytes_read, n, i;
	struct stat fs[2];
	u_char *content[2];
	double result;
	trie ngtrie;

	n		= 0;
	result		= 0;
	dotprod		= 0;
	sqrnorm1	= 0;
	sqrnorm2	= 0;
	result		= 0;
	bytes_read	= 0;
	content[0]	= NULL;
	content[1]	= NULL;
	ngtrie		= NULL;

	if (argc < 4) {
		fprintf(stdout, "Usage: %s n file1 file2\n", argv[0]);
		exit(EXIT_SUCCESS);
	}

	if ((n = atoi(argv[1])) == 0) n = 3;


	/* mmap files */
	for (i=0; i<2; i++) {
		if ((fd = open(argv[i+2], O_RDONLY)) == -1) {
			fprintf(stderr, "Error - Unable to open file: %s.\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
		if (fstat(fd, &fs[i]) != 0) {
			fprintf(stderr, "Error - Unable to get file size: %s.\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
		if (fs[i].st_size < 1) {
			fprintf(stdout, "File %s is empty.\n", argv[i+2]);
			exit(EXIT_SUCCESS);
		}
		if ((content[i] = mmap(0, fs[i].st_size, PROT_READ, MAP_SHARED, fd, 0)) == MAP_FAILED) {
			fprintf(stderr, "Error - Unable to map file into memory: %s.\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
		close(fd);
	}


	/* don't be shy, put in a trie */
	if ((ngtrie = build_ngram_trie(n, content[0], content[1], fs[0].st_size, fs[1].st_size)) == NULL) {
		printf("No trie built.\n");
		exit(EXIT_SUCCESS);
	}


	/* calculate vector lenghts and delete trie */ 
	calc_and_del_trie(ngtrie);


	/* calculate similarity */
	if (isnan(result = 100-(100*acos(dotprod/(sqrt(sqrnorm1)*sqrt(sqrnorm2)))/1.5707963))) result = 100;
	fprintf(stdout, "Similarity: %.2f%%.\n", result);


	if ((munmap(content[0], fs[0].st_size) != 0) || (munmap(content[1], fs[1].st_size) != 0)) {
		fprintf(stderr, "Unmapping files failed: %s.\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	
	return(EXIT_SUCCESS);
}
