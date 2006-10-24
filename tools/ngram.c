/* ngram.c
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
 * ngram calculates the similarity between two input files
 * using n-grams.
 *
 * The similarity in percent is printed to stdout.
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
#include <math.h>

#define max(a, b) ((a) > (b) ? a : b)

struct _avl_node;
typedef struct _avl_node *pos;
typedef struct _avl_node *avl_tree;

typedef struct _ngram {
	u_char *key;
	int freq1;
	int freq2;
} ngram;


typedef struct _avl_node {
	ngram *ng;
	avl_tree left;
	avl_tree right;
	int height;
} avl_node;


avl_tree avl_del_tree(avl_tree t) {
	if (t) {
		avl_del_tree(t->left);
		avl_del_tree(t->right);
		free(t);
	}
	return(NULL);
}


pos avl_find(ngram *x, avl_tree t, int n) {
	if (t == NULL) return(NULL);
	if (memcmp(x->key, t->ng->key, n) < 0) return avl_find(x, t->left, n);
	else if (memcmp(x->key, t->ng->key, n) > 0) return(avl_find(x, t->right, n));

	return(t);
}


static int avl_height(pos p) {
	if(p == NULL) return(-1);
	return(p->height);
}


static pos avl_single_lrot(pos k2) {
	pos k1;

	k1 = k2->left;
	k2->left = k1->right;
	k1->right = k2;

	k2->height = max(avl_height(k2->left), avl_height(k2->right)) + 1;
	k1->height = max(avl_height(k1->left), k2->height) + 1;

	return(k1);
}


static pos avl_single_rrot(pos k1) {
	pos k2;

	k2 = k1->right;
	k1->right = k2->left;
	k2->left = k1;

	k1->height = max(avl_height(k1->left), avl_height(k1->right)) + 1;
	k2->height = max(avl_height(k2->right), k1->height) + 1;

	return(k2);
}


static pos avl_double_lrot(pos k3) {
	k3->left = avl_single_rrot(k3->left);

	return(avl_single_lrot(k3));
}


static pos avl_double_rrot(pos k3) {
	k3->right = avl_single_lrot(k3->right);

	return(avl_single_rrot(k3));
}


avl_tree avl_ins(ngram *x, avl_tree t, int n, int id) {
	if (t == NULL) {
		if (((t = malloc(sizeof(avl_node))) == NULL) ||
		    ((t->ng = malloc(sizeof(ngram))) == NULL) ||
		    ((t->ng->key = malloc(n)) == NULL)) {
			fprintf(stderr, "Could not allocate memory: %s.\n", strerror(errno));
			exit(1);
		} else {
			memcpy(&(t->ng), &x, sizeof(ngram));
			memcpy(t->ng->key, x->key, n);
			t->height = 0;
			t->left = t->right = NULL;
				
			if (id == 0) t->ng->freq1 = 1;
			else t->ng->freq2 = 1;
		}
	} else if (memcmp(x->key, t->ng->key, n) < 0) {
		t->left = avl_ins(x, t->left, n, id);
		if (avl_height(t->left) - avl_height(t->right) == 2)
			if (memcmp(x->key, t->left->ng->key, n) < 0) t = avl_single_lrot(t);
			else t = avl_double_lrot(t);
	} else if (memcmp(x->key, t->ng->key, n) > 0) {
		t->right = avl_ins(x, t->right, n, id);
		if (avl_height(t->right) - avl_height(t->left) == 2)
			if (memcmp(x->key, t->right->ng->key, n) > 0) t = avl_single_rrot(t);
			else t = avl_double_rrot(t);
	} else {
		/* ngram already in tree, just update x's frequency */
		t = avl_find(x, t, n);
		if (id == 0) t->ng->freq1++;
		else t->ng->freq2++;
	}

	t->height = max(avl_height(t->left), avl_height(t->right)) + 1;
	return(t);
}


avl_tree calc_ngrams(int n, const u_char *data1, const u_char *data2, ssize_t len1, ssize_t len2) {
	int i, dim;
	ngram *new;
	avl_tree ngtree;

	new = NULL;
	dim = 0;

	bzero(&ngtree, sizeof(avl_node));

	/* process first data string */
	for (i=0; i<=len1-n; i++) {
		if (((new = malloc(sizeof(ngram))) == NULL) || ((new->key = malloc(n)) == NULL)) {
			fprintf(stderr, "Could not allocate memory: %s.\n", strerror(errno));
			exit(1);
		}
		new->freq1 = 0;
		new->freq2 = 0;
		memcpy(new->key, &data1[i], n);

		ngtree = avl_ins(new, ngtree, n, 0);
	}

	/* process second data string */
	for (i=0; i<=len2-n; i++) {
		if (((new = malloc(sizeof(ngram))) == NULL) || ((new->key = malloc(n)) == NULL)) {
			fprintf(stderr, "Could not allocate memory: %s.\n", strerror(errno));
			exit(1);
		}
		new->freq1 = 0;
		new->freq2 = 0;
		memcpy(new->key, &data2[i], n);

		ngtree = avl_ins(new, ngtree, n, 1);
	}

	return(ngtree);
}


void calc_lens(avl_tree t, float *len1, float *len2, float *dotproduct) {
	if(t == NULL) return;

	if (t->left) calc_lens(t->left, len1, len2, dotproduct);
	if (t->right) calc_lens(t->right, len1, len2, dotproduct);
	*len1 += pow(t->ng->freq1, 2);
	*len2 += pow(t->ng->freq2, 2);
	*dotproduct += (t->ng->freq1 * t->ng->freq2);
	
	return;
}


int main(int argc, char *argv[]) {
	int fd, bytes_read, n;
	struct stat fs1, fs2;
	u_char *content1, *content2;
	float dotproduct, len1, len2, result;
	avl_tree ngtree;

	n = 0;
	bytes_read = 0;
	len1 = 0;
	len2 = 0;
	result = 0;
	dotproduct = 0;
	result = 0;

	if (argc < 4) {
		fprintf(stdout, "Usage: %s n file1 file2\n", argv[0]);
		exit(0);
	}

	if ((n = atoi(argv[1])) == 0) n = 3;

	/* open file */
	if ((fd = open(argv[2], O_RDONLY)) == -1) {
		fprintf(stderr, "Error - Unable to open file: %s.\n", strerror(errno));
		exit(1);
	}

	/* get file size */
	if (fstat(fd, &fs1) != 0) {
		fprintf(stderr, "Error - Unable to get file size: %s.\n", strerror(errno));
		exit(1);
	}
	if (fs1.st_size < 1) {
		fprintf(stdout, "File is empty.\n");
		exit(0);
	}

	/* map file content into memory */
	if ((content1 = (u_char *) malloc(fs1.st_size)) == NULL) {
		fprintf(stderr, "Error - Unable to allocate memory: %s.\n", strerror(errno));
		exit(1);
	}
	bzero(content1, fs1.st_size);
	bytes_read = 0;
	if ((bytes_read = read(fd, content1+bytes_read, fs1.st_size)) < fs1.st_size) {
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

	/* open file */
	if ((fd = open(argv[3], O_RDONLY)) == -1) {
		fprintf(stderr, "Error - Unable to open file: %s.\n", strerror(errno));
		exit(1);
	}

	/* get file size */
	if (fstat(fd, &fs2) != 0) {
		fprintf(stderr, "Error - Unable to get file size: %s.\n", strerror(errno));
		exit(1);
	}
	if (fs2.st_size < 1) {
		fprintf(stdout, "File is empty.\n");
		exit(0);
	}

	/* map file content into memory */
	if ((content2 = (u_char *) malloc(fs2.st_size)) == NULL) {
		fprintf(stderr, "Error - Unable to allocate memory: %s.\n", strerror(errno));
		exit(1);
	}
	bzero(content2, fs2.st_size);
	bytes_read = 0;
	if ((bytes_read = read(fd, content2+bytes_read, fs2.st_size)) < fs2.st_size) {
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


	/* calculate ngrams */
	fprintf(stdout, "Calculating ngrams.\n");
	ngtree = calc_ngrams(n, content1, content2, fs1.st_size, fs2.st_size);

	/* calculate similarity */
	fprintf(stdout, "Calculating similarity.\n");
	calc_lens(ngtree, &len1, &len2, &dotproduct);
	avl_del_tree(ngtree);

	len1 = sqrt(len1);
	len2 = sqrt(len2);

	if (isnan(result = 100-(100*acos(dotproduct/(len1*len2))/1.5707963)))
		result = 100;

	fprintf(stdout, "Similarity: %.2f%%.\n", result);

	free(content1);
	free(content2);
	
	return(0);
}
