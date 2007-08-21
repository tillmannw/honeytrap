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

#include <ctype.h>
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
	u_int16_t array_size;
	u_int32_t freq1;
	u_int32_t freq2;
	trie childlist;
} trie_node;


double sqrnorm1, sqrnorm2, dotprod;


trie find_node(trie t, u_int16_t size, u_char key) {
	u_int16_t i=0;
	u_int16_t high, low;
	
	if (t == NULL) return(NULL);

	for (low=0, high=(size-1); high-low>0; ) {
		i = (high+low)/2;
		if (key <= (t+i)->key) high = i;
		else{
			i = (high+low+1)/2;
			low = i;
		}
	}
	return(t[i].key == key ? &t[i] : NULL);
}

trie insert_new_child_node(trie parent, u_char key, u_char snum) {
	u_int16_t i = 0;
	int high, low;
	trie t = NULL;

	if ((t = realloc(parent->childlist, sizeof(trie_node)*(parent->array_size+1))) == NULL) {
		fprintf(stderr, "Error - Unable to allocate memory: %s.\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	parent->childlist = t;
	parent->array_size++;

	if (parent->array_size > 1) {
		/* multiple nodes, binary-search array position and memmove */
		i = 0;
		for (low=0, high=(parent->array_size-1); high-low>0; ) {
			i = (high+low)/2;
			if (key <= (t+i)->key) high = i;
			else {
				i = (high+low+1)/2;
				low = i;
			}
		}
		if (key < t[i].key) memmove(&t[i+1], &t[i], (parent->array_size-i-1)*(sizeof(trie_node)));
		else  {
			if (i != parent->array_size-2) {
				memmove(&t[i+2], &t[i+1], (parent->array_size-i-1)*(sizeof(trie_node)));
			}
		}
		t = &t[i];
		
	}

	memset(t, 0, sizeof(trie_node));
	t->key = key;	// set first element
	if (snum) t->freq2=1;
	else t->freq1=1;

	return(t);
}


/* inserts an ngram into the trie or update its frequency */
void ngram_ins(trie t, const u_char *data, ssize_t n, u_char snum) {
	ssize_t k;
	trie target_node;

	if (t == NULL) {
		fprintf(stderr, "Error - Cannot insert into empty trie.\n");
		exit(EXIT_FAILURE);
	}

	for (k=0; k<n; k++) {
		/* search for key in child list */
		if ((target_node = find_node(t->childlist, t->array_size, data[k])) == NULL) {
			if ((t = insert_new_child_node(t, data[k], snum)) == NULL) {
				fprintf(stderr, "Error - Unable to create new trie node: %s.\n", strerror(errno));
				exit(EXIT_FAILURE);
			} 
		} else {
			t = target_node;
			/* we're always at the right node here, update frequency */
			(snum == 0) ? t->freq1++ : t->freq2++;
		}
	}
	return;
}



/* builds a trie of ngrams */
trie build_ngram_trie(trie t, int n, const u_char *data1, const u_char *data2, ssize_t len1, ssize_t len2) {
	ssize_t pos = 0;

	/* process data strings */
	if (len1 < len2) {
		for (pos=0; pos < len1-n+1; pos++) ngram_ins(t, &data1[pos], n, 0);
		for (pos=0; pos < len2-n+1; pos++) ngram_ins(t, &data2[pos], n, 1);
	} else {
		for (pos=0; pos < len2-n+1; pos++) ngram_ins(t, &data2[pos], n, 0);
		for (pos=0; pos < len1-n+1; pos++) ngram_ins(t, &data1[pos], n, 1);
	}

	return(t);
}


void calc_and_del_trie(trie t, u_int16_t node_size, int depth) {
	u_int16_t i = 0;

	if (t == NULL) return;

	for (i=0; i<node_size; i++) {
		if (t->childlist == NULL) {
			sqrnorm1 += pow(t[i].freq1, 2);
			sqrnorm2 += pow(t[i].freq2, 2);
			dotprod += t[i].freq1 * t[i].freq2;
		} else calc_and_del_trie(t[i].childlist, t[i].array_size, depth+1);
	}
	free(t);

	return;
}


int main(int argc, char *argv[]) {
	int fd, bytes_read, n, i;
	struct stat fs[2];
	u_char *content[2];
	double result;
	trie_node ngtrie;

	n		= 0;
	result		= 0;
	dotprod		= 0;
	sqrnorm1	= 0;
	sqrnorm2	= 0;
	result		= 0;
	bytes_read	= 0;
	content[0]	= NULL;
	content[1]	= NULL;

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
	memset(&ngtrie, 0, sizeof(trie_node));
	if ((build_ngram_trie(&ngtrie, n, content[0], content[1], fs[0].st_size, fs[1].st_size)) == NULL) {
		printf("No trie built.\n");
		exit(EXIT_SUCCESS);
	}

	/* calculate vector lenghts and delete trie */ 
	result = dotprod = sqrnorm1 = sqrnorm2 = 0;
	calc_and_del_trie(ngtrie.childlist, ngtrie.array_size, 0);

	/* calculate similarity */
	if (isnan(result = 100-(100*acos(dotprod/(sqrt(sqrnorm1)*sqrt(sqrnorm2)))/1.5707963))) result = 100;
	fprintf(stdout, "Similarity: %.2f%%.\n", result);

	if ((munmap(content[0], fs[0].st_size) != 0) || (munmap(content[1], fs[1].st_size) != 0)) {
		fprintf(stderr, "Unmapping files failed: %s.\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	
	return(EXIT_SUCCESS);
}

