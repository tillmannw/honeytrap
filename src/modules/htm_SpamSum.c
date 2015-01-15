/* htm_SpamSum.c
 * Copyright (C) 2006-2015 Tillmann Werner <tillmann.werner@gmx.de>
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
 * Description:
 *   This honeytrap module calculates a locality sensitive hashing
 *   signature using the spamsum algorithm from Andrew Tridgell and
 *   compares it to a signature file.
 */

#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>

#include <honeytrap.h>
#include <logging.h>
#include <readconf.h>
#include <conftree.h>
#include <util.h>
#include <plughook.h>

#include "htm_SpamSum.h"

const char module_name[]="SpamSum";
const char module_version[]="1.0.1";

static const char *config_keywords[] = {
	"md5sum_sigfile",
	"spamsum_sigfile"
};

const char *md5sum_filename;
const char *spamsum_filename;


#define SPAMSUM_LENGTH 64	/* the output is a string of length 64 in base64 */
#define MIN_BLOCKSIZE 3
#define HASH_PRIME 0x01000193
#define HASH_INIT 0x28021967
#define ROLLING_WINDOW 7

#ifndef MIN
#define MIN(a,b) ((a)<(b)?(a):(b))
#endif

#ifndef MAX
#define MAX(a,b) ((a)>(b)?(a):(b))
#endif

#define FLAG_IGNORE_WHITESPACE 1
#define FLAG_IGNORE_HEADERS 2

static struct {
	u_char window[ROLLING_WINDOW];
	u_int32_t h1, h2, h3;
	u_int32_t n;
} roll_state;


void plugin_config(void) {
	register_plugin_confopts(module_name, config_keywords, sizeof(config_keywords)/sizeof(char *));
	if (process_conftree(config_tree, config_tree, plugin_process_confopts, NULL) == NULL) {
		fprintf(stderr, "  Error - Unable to process configuration tree for plugin %s.\n", module_name);
		exit(EXIT_FAILURE);
	}
	return;
}

void plugin_init(void) {
	plugin_register_hooks();
	return;
}

void plugin_unload(void) {
	unhook(PPRIO_POSTPROC, module_name, "calc_spamsum");
	return;
}

void plugin_register_hooks(void) {
	logmsg(LOG_DEBUG, 1, "    Plugin %s: Registering hooks.\n", module_name);
	add_attack_func_to_list(PPRIO_POSTPROC, module_name, "calc_spamsum", (void *) calc_spamsum);

	return;
}

conf_node *plugin_process_confopts(conf_node *tree, conf_node *node, void *opt_data) {
	char		*value = NULL;
	conf_node	*confopt = NULL;

	if ((confopt = check_keyword(tree, node->keyword)) == NULL) return(NULL);

	while (node->val) {
		if ((value = malloc(node->val->size+1)) == NULL) {
			perror("  Error - Unable to allocate memory");
			exit(EXIT_FAILURE);
		}
		memset(value, 0, node->val->size+1);
		memcpy(value, node->val->data, node->val->size);

		node->val = node->val->next;

		if OPT_IS("spamsum_sigfile") {
			spamsum_filename = value;
		} else if OPT_IS("md5sum_sigfile") {
			md5sum_filename = value;
		} else {
			fprintf(stderr, "  Error - Invalid configuration option for plugin %s: %s\n", module_name, node->keyword);
			exit(EXIT_FAILURE);
		}
	}
	return(node);
}

int calc_spamsum(Attack *attack) {
	u_char sig_match;
	u_int32_t block_size, threshold, score;
	char *sum, sig[BUFSIZ];
	FILE* sigfile, *hashfile;

	sig_match	= 0;
	block_size	= 0;
	threshold	= 90;
	score		= 0;
	sum		= NULL;
	sigfile		= NULL;
	hashfile	= NULL;

	/* no data - nothing todo */
	if ((attack->a_conn.payload.size == 0) || (attack->a_conn.payload.data == NULL)) {
		logmsg(LOG_DEBUG, 1, "SpamSum - No data received, won't calculate spamsum.\n");
		return(0);
	}

	logmsg(LOG_DEBUG, 1, "SpamSum - Calculating hashes.\n");

	/* check for MD5 hash match before calculating spamsum */
	logmsg(LOG_DEBUG, 1, "SpamSum - Searching MD5 hash file for exact match.\n");
	if ((hashfile = fopen(md5sum_filename, "r")) == NULL) {
		logmsg(LOG_ERR, 1, "SpamSum error - Could not open MD5 hash file %s: %s.\n", md5sum_filename, strerror(errno));
		return(0);
	}
	logmsg(LOG_DEBUG, 1, "SpamSum - MD5 hash file successfully opened.\n");

	/* search MD5 hash file for calculated sum */
	while((sig_match == 0) && (!feof(hashfile))) {
		bzero(sig, BUFSIZ);
		if ((fgets(sig, BUFSIZ-1, hashfile) == NULL) && (!feof(hashfile))) {
			logmsg(LOG_ERR, 1, "SpamSum error - Could not read MD5 hash from signature file: %s.\n", strerror(errno));
			fclose(hashfile);
			return(0);
		}
		if ((sig[0]) && (!feof(hashfile))) {
			if (sig[32] == '\n') sig[32] = 0;
			logmsg(LOG_DEBUG, 1, "SpamSum - Comparing with %s.\n", sig);
			if (strcmp(attack->a_conn.payload.md5sum, sig) == 0) sig_match = 1;
		}
	}
	fclose(hashfile);
	logmsg(LOG_DEBUG, 1, "SpamSum - MD5 hash file processed.\n");

	/* hash is not in signature file, append it */
	if (sig_match == 0) {
		if ((hashfile = fopen(md5sum_filename, "a")) == NULL) {
			logmsg(LOG_ERR, 1, "SpamSum error - Could not open MD5 hash file %s: %s.\n", md5sum_filename, strerror(errno));
			return(0);
		}
		errno = 0;
		if (fprintf(hashfile, "%s\n", attack->a_conn.payload.md5sum) != 33) {
			logmsg(LOG_ERR, 1, "SpamSum error - Could not append MD5 hash to signature file: %s.\n", strerror(errno));
			fclose(hashfile);
			return(0);
		}
		logmsg(LOG_INFO, 1, "SpamSum - MD5 hash appended to signature file.\n");
		fclose(hashfile);
	} else {
		logmsg(LOG_INFO, 1, "SpamSum - Found an exact MD5 hash match.\n");
		return(1);
	}


	/* calculate spamsum */
	logmsg(LOG_NOISY, 1, "SpamSum - Calculating spamsum.\n");
	sum = spamsum(attack->a_conn.payload.data, attack->a_conn.payload.size, block_size);
	logmsg(LOG_DEBUG, 1, "SpamSum - Spamsum is %s.\n", sum);

	logmsg(LOG_DEBUG, 1, "SpamSum - Searching signature file for exact match.\n");
	if ((sigfile = fopen(spamsum_filename, "r")) == NULL) {
		logmsg(LOG_ERR, 1, "SpamSum error - Could not open SpamSum hash file %s: %s.\n", spamsum_filename, strerror(errno));
		return(0);
	}
	logmsg(LOG_DEBUG, 1, "SpamSum - Signature file successfully opened.\n");

	/* search signature file for calculated sum */
	while((sig_match == 0) && (!feof(sigfile))) {
		bzero(sig, BUFSIZ);
		if ((fgets(sig, BUFSIZ-1, sigfile) == NULL) && (!feof(sigfile))) {
			logmsg(LOG_ERR, 1, "SpamSum error - Could not read spamsum from signature file: %s.\n", strerror(errno));
			fclose(sigfile);
			return(0);
		}
		if ((sig[0]) && (!feof(sigfile))) {
			logmsg(LOG_DEBUG, 1, "SpamSum - Comparing with %s", sig);
			if (strcmp(sum, sig) == 0) sig_match = 1;
		}
	}
	fclose(sigfile);
	logmsg(LOG_DEBUG, 1, "SpamSum - Signature file processed.\n");
	
	/* sum is not in signature file, append it */
	if (sig_match == 0) {
		score = spamsum_match_db(spamsum_filename, sum, threshold);
		logmsg(LOG_INFO, 1, "SpamSum - Spamsum match score is %u.\n", score);

		if ((sigfile = fopen(spamsum_filename, "a")) == NULL) {
			logmsg(LOG_ERR, 1, "SpamSum error - Could not open SpamSum hash file %s: %s.\n", spamsum_filename, strerror(errno));
			return(0);
		}
		strncat(sum, "\n", 1);
		if (fprintf(sigfile, "%s", sum) != strlen(sum)) {
			logmsg(LOG_ERR, 1, "SpamSum error - Could not append spamsum to signature file: %s.\n", strerror(errno));
			fclose(sigfile);
			return(0);
		}
		logmsg(LOG_NOISY, 1, "SpamSum - Locality sensitive hash value appended to signature file.\n");
		fclose(sigfile);
	}
	
	return(1);
}


/* take a message of length 'length' and return a spamsum of that message, prefixed by the selected blocksize */
char *spamsum(const u_char *in, size_t length, u_int32_t bsize) {
	const char *b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	char *ret, *p;
	u_int32_t total_chars;
	u_int32_t h, h2, h3;
	u_int32_t i, j, k;
	u_int32_t block_size;
	char ret2[SPAMSUM_LENGTH/2 + 1];

	total_chars = length;

	if (bsize == 0) {
	/* guess a reasonable block size */
		block_size = MIN_BLOCKSIZE;
		while (block_size * SPAMSUM_LENGTH < total_chars) {
			block_size = block_size * 2;
		}
	} else {
		block_size = bsize;
	}

	ret = malloc(SPAMSUM_LENGTH + SPAMSUM_LENGTH/2 + 20);
	if (!ret) return NULL;

again:
	/* the first part of the spamsum signature is the blocksize */
	snprintf(ret, 12, "%u:", block_size);
	p = ret + strlen(ret);

	memset(p, 0, SPAMSUM_LENGTH+1);
	memset(ret2, 0, sizeof(ret2));

	k = j = 0;
	h3 = h2 = HASH_INIT;
	h = roll_reset();

	for (i=0; i<length; i++) {
		/* 
		   at each character we update the rolling hash and
		   the normal hash. When the rolling hash hits the
		   reset value then we emit the normal hash as a
		   element of the signature and reset both hashes
		*/
		h = roll_hash(in[i]);
		h2 = sum_hash(in[i], h2);
		h3 = sum_hash(in[i], h3);

		if (h % block_size == (block_size-1)) {
			/* we have hit a reset point. We now emit a
			   hash which is based on all chacaters in the
			   piece of the message between the last reset
			   point and this one */
			p[j] = b64[h2 % 64];
			if (j < SPAMSUM_LENGTH-1) {
				/* we can have a problem with the tail
				   overflowing. The easiest way to
				   cope with this is to only reset the
				   second hash if we have room for
				   more characters in our
				   signature. This has the effect of
				   combining the last few pieces of
				   the message into a single piece */
				h2 = HASH_INIT;
				j++;
			}
		}

		/* this produces a second signature with a block size
		   of block_size*2. By producing dual signatures in
		   this way the effect of small changes in the message
		   size near a block size boundary is greatly reduced. */
		if (h % (block_size*2) == ((block_size*2)-1)) {
			ret2[k] = b64[h3 % 64];
			if (k < SPAMSUM_LENGTH/2-1) {
				h3 = HASH_INIT;
				k++;
			}
		}
	}

	/* if we have anything left then add it to the end. This
	   ensures that the last part of the message is always
	   considered */
	if (h != 0) {
		p[j] = b64[h2 % 64];
		ret2[k] = b64[h3 % 64];
	}

	strcat(p+j, ":");
	strcat(p+j, ret2);

	/* our blocksize guess may have been way off - repeat if necessary */
	if (bsize == 0 && block_size > MIN_BLOCKSIZE && j < SPAMSUM_LENGTH/2) {
		block_size = block_size / 2;
		goto again;
	}

	return ret;
}

/*
  a rolling hash, based on the Adler checksum. By using a rolling hash
  we can perform auto resynchronisation after inserts/deletes

  internally, h1 is the sum of the bytes in the window and h2
  is the sum of the bytes times the index

  h3 is a shift/xor based rolling hash, and is mostly needed to ensure that
  we can cope with large blocksize values
*/
static inline u_int32_t roll_hash(u_char c) {
	roll_state.h2 -= roll_state.h1;
	roll_state.h2 += ROLLING_WINDOW * c;

	roll_state.h1 += c;
	roll_state.h1 -= roll_state.window[roll_state.n % ROLLING_WINDOW];

	roll_state.window[roll_state.n % ROLLING_WINDOW] = c;
	roll_state.n++;

	roll_state.h3 = (roll_state.h3 << 5) & 0xFFFFFFFF;
	roll_state.h3 ^= c;

	return roll_state.h1 + roll_state.h2 + roll_state.h3;
}


/* reset the state of the rolling hash and return the initial rolling hash value */
static u_int32_t roll_reset(void) {
	memset(&roll_state, 0, sizeof(roll_state));
	return 0;
}


/* a simple non-rolling hash, based on the FNV hash */
static inline u_int32_t sum_hash(u_char c, u_int32_t h) {
	h *= HASH_PRIME;
	h ^= c;
	return h;
}


/* given two spamsum strings return a value indicating the degree to which they match.  */
u_int32_t spamsum_match(const char *str1, const char *str2) {
	u_int32_t block_size1, block_size2;
	u_int32_t score = 0;
	char *s1, *s2;
	char *s1_1, *s1_2;
	char *s2_1, *s2_2;

	/* each spamsum is prefixed by its block size */
	if (sscanf(str1, "%u:", &block_size1) != 1 ||
	    sscanf(str2, "%u:", &block_size2) != 1) {
		return 0;
	}

	/* if the blocksizes don't match then we are comparing
	   apples to oranges ... */
	if (block_size1 != block_size2 && 
	    block_size1 != block_size2*2 &&
	    block_size2 != block_size1*2) {
		return 0;
	}

	/* move past the prefix */
	str1 = strchr(str1, ':');
	str2 = strchr(str2, ':');

	if (!str1 || !str2) {
		/* badly formed ... */
		return 0;
	}

	/* there is very little information content is sequences of
	   the same character like 'LLLLL'. Eliminate any sequences
	   longer than 3. This is especially important when combined
	   with the has_common_substring() test below. */
	s1 = eliminate_sequences(str1+1);
	s2 = eliminate_sequences(str2+1);

	if (!s1 || !s2) return 0;

	/* now break them into the two pieces */
	s1_1 = s1;
	s2_1 = s2;

	s1_2 = strchr(s1, ':');
	s2_2 = strchr(s2, ':');

	if (!s1_2 || !s2_2) {
		/* a signature is malformed - it doesn't have 2 parts */
		free(s1); free(s2);
		return 0;
	}

	*s1_2++ = 0;
	*s2_2++ = 0;

	/* each signature has a string for two block sizes. We now
	   choose how to combine the two block sizes. We checked above
	   that they have at least one block size in common */
	if (block_size1 == block_size2) {
		u_int32_t score1, score2;
		score1 = score_strings(s1_1, s2_1, block_size1);
		score2 = score_strings(s1_2, s2_2, block_size2);
		score = MAX(score1, score2);
	} else if (block_size1 == block_size2*2) {
		score = score_strings(s1_1, s2_2, block_size1);
	} else {
		score = score_strings(s1_2, s2_1, block_size2);
	}

	free(s1);
	free(s2);

	return score;
}


/* return the maximum match for a file containing a list of spamsums */
u_int32_t spamsum_match_db(const char *fname, const char *sum, u_int32_t threshold) {
	FILE *f;
	char line[100];
	u_int32_t best = 0;

	f = fopen(fname, "r");
	if (!f) return 0;

	/* on each line of the database we compute the spamsum match
	   score. We then pick the best score */
	while (fgets(line, sizeof(line)-1, f)) {
		u_int32_t score;
		int len;
		len = strlen(line);
		if (line[len-1] == '\n') line[len-1] = 0;

		score = spamsum_match(sum, line);

		if (score > best) {
			best = score;
			if (best >= threshold) break;
		}
	}

	fclose(f);

	return best;
}


/* eliminate sequences of longer than 3 identical characters. These
  sequences contain very little information so they tend to just bias
  the result unfairly */
static char *eliminate_sequences(const char *str) {
	char *ret;
	int i, j, len;

	ret = strdup(str);
	if (!ret) return NULL;

	len = strlen(str);

	for (i=j=3;i<len;i++) {
		if (str[i] != str[i-1] ||
		    str[i] != str[i-2] ||
		    str[i] != str[i-3]) {
			ret[j++] = str[i];
		}
	}

	ret[j] = 0;

	return ret;
}


/* this is the low level string scoring algorithm. It takes two strings
  and scores them on a scale of 0-100 where 0 is a terrible match and
  100 is a great match. The block_size is used to cope with very small
  messages.  */
static unsigned score_strings(const char *s1, const char *s2, u_int32_t block_size) {
	u_int32_t score;
	u_int32_t len1, len2;

	len1 = strlen(s1);
	len2 = strlen(s2);

	if (len1 > SPAMSUM_LENGTH || len2 > SPAMSUM_LENGTH) {
		/* not a real spamsum signature? */
		return 0;
	}

	/* the two strings must have a common substring of length
	   ROLLING_WINDOW to be candidates */
	if (has_common_substring(s1, s2) == 0) {
		return 0;
	}

	/* compute the edit distance between the two strings. The edit distance gives
	   us a pretty good idea of how closely related the two strings are */
	score = edit_distn((char *)s1, len1, (char *)s2, len2);

	/* scale the edit distance by the lengths of the two
	   strings. This changes the score to be a measure of the
	   proportion of the message that has changed rather than an
	   absolute quantity. It also copes with the variability of
	   the string lengths. */
	score = (score * SPAMSUM_LENGTH) / (len1 + len2);

	/* at this stage the score occurs roughly on a 0-64 scale,
	 * with 0 being a good match and 64 being a complete
	 * mismatch */

	/* rescale to a 0-100 scale (friendlier to humans) */
	score = (100 * score) / 64;

	/* it is possible to get a score above 100 here, but it is a
	   really terrible match */
	if (score >= 100) return 0;

	/* now re-scale on a 0-100 scale with 0 being a poor match and
	   100 being a excellent match. */
	score = 100 - score;

	/* when the blocksize is small we don't want to exaggerate the match size */
	if (score > block_size/MIN_BLOCKSIZE * MIN(len1, len2)) {
		score = block_size/MIN_BLOCKSIZE * MIN(len1, len2);
	}

	return score;
}


/* we only accept a match if we have at least one common substring in
   the signature of length ROLLING_WINDOW. This dramatically drops the
   false positive rate for low score thresholds while having
   negligable affect on the rate of spam detection.

   return 1 if the two strings do have a common substring, 0 otherwise */
static int has_common_substring(const char *s1, const char *s2) {
	int i, j;
	int num_hashes;
	u_int32_t hashes[SPAMSUM_LENGTH];

	/* there are many possible algorithms for common substring
	   detection. In this case I am re-using the rolling hash code
	   to act as a filter for possible substring matches */

	roll_reset();
	memset(hashes, 0, sizeof(hashes));

	/* first compute the windowed rolling hash at each offset in
	   the first string */
	for (i=0;s1[i];i++) {
		hashes[i] = roll_hash((u_char)s1[i]);
	}
	num_hashes = i;

	roll_reset();

	/* now for each offset in the second string compute the
	   rolling hash and compare it to all of the rolling hashes
	   for the first string. If one matches then we have a
	   candidate substring match. We then confirm that match with
	   a direct string comparison */
	for (i=0;s2[i];i++) {
		u_int32_t h = roll_hash((u_char)s2[i]);
		if (i < ROLLING_WINDOW-1) continue;
		for (j=ROLLING_WINDOW-1;j<num_hashes;j++) {
			if (hashes[j] != 0 && hashes[j] == h) {
				/* we have a potential match - confirm it */
				if (strlen(s2+i-(ROLLING_WINDOW-1)) >= ROLLING_WINDOW && 
				    strncmp(s2+i-(ROLLING_WINDOW-1), 
					    s1+j-(ROLLING_WINDOW-1), 
					    ROLLING_WINDOW) == 0) {
					return 1;
				}
			}
		}
	}

	return 0;
}


#define MIN_DIST 100

#define	TRN_SPEEDUP		/* Use a less-general version of the
				   routine, one that's better for trn.
				   All change costs are 1, and it's okay
				   to terminate if the edit distance is
				   known to exceed MIN_DIST */

#define THRESHOLD 4000		/* worry about allocating more memory only
				   when this # of bytes is exceeded */
#define STRLENTHRESHOLD ((int) ((THRESHOLD / sizeof (int) - 3) / 2))

#define SAFE_ASSIGN(x,y) (((x) != NULL) ? (*(x) = (y)) : (y))

#define swap_int(x,y)  (_iswap = (x), (x) = (y), (y) = _iswap)
#define swap_char(x,y) (_cswap = (x), (x) = (y), (y) = _cswap)
#define min3(x,y,z) (_mx = (x), _my = (y), _mz = (z), (_mx < _my ? (_mx < _mz ? _mx : _mz) : (_mz < _my) ? _mz : _my))
#define min2(x,y) (_mx = (x), _my = (y), (_mx < _my ? _mx : _my))


static int insert_cost = 1;
static int delete_cost = 1;
#ifndef TRN_SPEEDUP
static int change_cost = 1;
static int swap_cost   = 1;
#endif

static int _iswap;			/* swap_int temp variable */
static char *_cswap;			/* swap_char temp variable */
static int _mx, _my, _mz;		/* min2, min3 temp variables */



/* edit_distn -- returns the edit distance between two strings, or -1 on failure */
int edit_distn(char *from, register int from_len, char *to, register int to_len) {
#ifndef TRN_SPEEDUP
    register int ins, del, ch;	  	/* local copies of edit costs */
#endif
    register int row, col, index;	/* dynamic programming counters */
    register int radix;			/* radix for modular indexing */
#ifdef TRN_SPEEDUP
    register int low;
#endif
    int *buffer;			/* pointer to storage for one row
					   of the d.p. array */
    static int store[THRESHOLD / sizeof (int)];
					/* a small amount of static
					   storage, to be used when the
					   input strings are small enough */

/* Handle trivial cases when one string is empty */

    if (from == NULL || !from_len)
	if (to == NULL || !to_len)
	    return 0;
	else
	    return to_len * insert_cost;
    else if (to == NULL || !to_len)
	return from_len * delete_cost;

/* Initialize registers */

    radix = 2 * from_len + 3;
#ifdef TRN_SPEEDUP
#define ins 1
#define del 1
#define ch 1
#define swap_cost 1
#else
    ins  = insert_cost;
    del  = delete_cost;
    ch   = change_cost;
#endif

/* Make   from   short enough to fit in the static storage, if it's at all
   possible */

    if (from_len > to_len && from_len > STRLENTHRESHOLD) {
	swap_int(from_len, to_len);
	swap_char(from, to);
#ifndef TRN_SPEEDUP
	swap_int(ins, del);
#endif
    } /* if from_len > to_len */

/* Allocate the array storage (from the heap if necessary) */

    if (from_len <= STRLENTHRESHOLD)
	buffer = store;
    else
	buffer = (int *) malloc(radix * sizeof (int));

/* Here's where the fun begins.  We will find the minimum edit distance
   using dynamic programming.  We only need to store two rows of the matrix
   at a time, since we always progress down the matrix.  For example,
   given the strings "one" and "two", and insert, delete and change costs
   equal to 1:

	   _  o  n  e
	_  0  1  2  3
	t  1  1  2  3
	w  2  2  2  3
	o  3  2  3  3

   The dynamic programming recursion is defined as follows:

	ar(x,0) := x * insert_cost
	ar(0,y) := y * delete_cost
	ar(x,y) := min(a(x - 1, y - 1) + (from[x] == to[y] ? 0 : change),
		       a(x - 1, y) + insert_cost,
		       a(x, y - 1) + delete_cost,
		       a(x - 2, y - 2) + (from[x] == to[y-1] &&
					  from[x-1] == to[y] ? swap_cost :
					  infinity))

   Since this only looks at most two rows and three columns back, we need
   only store the values for the two preceeding rows.  In this
   implementation, we do not explicitly store the zero column, so only 2 *
   from_len + 2   words are needed.  However, in the implementation of the
   swap_cost   check, the current matrix value is used as a buffer; we
   can't overwrite the earlier value until the   swap_cost   check has
   been performed.  So we use   2 * from_len + 3   elements in the buffer.
*/

#define ar(x,y,index) (((x) == 0) ? (y) * del : (((y) == 0) ? (x) * ins : \
	buffer[mod(index)]))
#define NW(x,y)	  ar(x, y, index + from_len + 2)
#define N(x,y)	  ar(x, y, index + from_len + 3)
#define W(x,y)	  ar(x, y, index + radix - 1)
#define NNWW(x,y) ar(x, y, index + 1)
#define mod(x) ((x) % radix)

    index = 0;

#ifdef DEBUG_EDITDIST
    printf("      ");
    for (col = 0; col < from_len; col++)
	printf(" %c ", from[col]);
    printf("\n   ");

    for (col = 0; col <= from_len; col++)
	printf("%2d ", col * del);
#endif

/* Row 0 is handled implicitly; its value at a given column is   col*del.
   The loop below computes the values for Row 1.  At this point we know the
   strings are nonempty.  We also don't need to consider swap costs in row
   1.

   COMMENT:  the indicies   row and col   below point into the STRING, so
   the corresponding MATRIX indicies are   row+1 and col+1.
*/

    buffer[index++] = min2(ins + del, (from[0] == to[0] ? 0 : ch));
#ifdef TRN_SPEEDUP
    low = buffer[mod(index + radix - 1)];
#endif

#ifdef DEBUG_EDITDIST
    printf("\n %c %2d %2d ", to[0], ins, buffer[index - 1]);
#endif

    for (col = 1; col < from_len; col++) {
	buffer[index] = min3(
		col * del + ((from[col] == to[0]) ? 0 : ch),
		(col + 1) * del + ins,
		buffer[index - 1] + del);
#ifdef TRN_SPEEDUP
	if (buffer[index] < low)
	    low = buffer[index];
#endif
	index++;

#ifdef DEBUG_EDITDIST
	printf("%2d ", buffer[index - 1]);
#endif

    } /* for col = 1 */

#ifdef DEBUG_EDITDIST
    printf("\n %c %2d ", to[1], 2 * ins);
#endif

/* Now handle the rest of the matrix */

    for (row = 1; row < to_len; row++) {
	for (col = 0; col < from_len; col++) {
	    buffer[index] = min3(
		    NW(row, col) + ((from[col] == to[row]) ? 0 : ch),
		    N(row, col + 1) + ins,
		    W(row + 1, col) + del);
	    if (from[col] == to[row - 1] && col > 0 &&
		    from[col - 1] == to[row])		    
		buffer[index] = min2(buffer[index],
			NNWW(row - 1, col - 1) + swap_cost);

#ifdef DEBUG_EDITDIST
	    printf("%2d ", buffer[index]);
#endif
#ifdef TRN_SPEEDUP
	    if (buffer[index] < low || col == 0)
		low = buffer[index];
#endif

	    index = mod(index + 1);
	} /* for col = 1 */
#ifdef DEBUG_EDITDIST
	if (row < to_len - 1)
	    printf("\n %c %2d ", to[row+1], (row + 2) * ins);
	else
	    printf("\n");
#endif
#ifdef TRN_SPEEDUP
	if (low > MIN_DIST)
	    break;
#endif
    } /* for row = 1 */

    row = buffer[mod(index + radix - 1)];
    if (buffer != store)
	free((char *) buffer);
    return row;
} /* edit_distn */
