/* htm_xmatch.c
 * Copyright (C) 2010-2015 Tillmann Werner <tillmann.werner@gmx.de>
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
 *   This module assumes that an input is xor-encoded and performs a
 *   matching of known patterns in order to extract the key and decode the
 *   data. Decoded attack strings are then further processed as virtual
 *   attacks. An example application is getting URLs from self-modifying
 *   shellcode without having to run any kind of emulation.
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#define _GNU_SOURCE

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <xmatch.h>

#include <honeytrap.h>
#include <logging.h>
#include <plughook.h>
#include <readconf.h>
#include <signals.h>


const char module_name[]="xmatch";
const char module_version[]="1.0.1";

static const char *config_keywords[] = {
	"xpattern_file",
};

const char *xpattern_file;

typedef struct {
	u_char	*data;
	size_t	len;
} xorkey_t;

xm_fsm_t *fsm;		// finite state machine
xm_string_t **p;	// array of patterns
size_t num_patterns;	// size of the above array
size_t maxlen;


// calculates the period of a string
size_t period(u_char *s, size_t len) {
	int i, j, period = len;
	for (i=1; i<len; ++i) {
		if (s[0] == s[i]) {
			for (j = i; j<len; ++j) {
				if (s[j-i] != s[j]) {
					period = len;
					break;
				}
				period = i;
			}
		}
		if (period < len) break;
	}

	return period;
}

int handle_match(void *pattern_p, int offset, void *input_p) {
	xm_string_t *pattern = pattern_p;
	xm_string_t *input = input_p;
	xorkey_t *key = input->userdata;

	logmsg(LOG_DEBUG, 1, "xmatch - Found a match at offset 0x%08x\n", (unsigned int) input->offset + offset);

	if ((key->data = malloc(pattern->len)) == NULL) {
		logmsg(LOG_ERR, 1, "xmatch error - Unable to allocate memory: %s.\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	key->len = pattern->len;

	size_t i, j;
	int nonzero_key = 0;

	for (j=0; j<pattern->len; ++j) {
		key->data[j] = input->data[offset + j] ^ pattern->data[j];
		if (key->data[j] != 0) nonzero_key = 1;
	}

	// if the key consists of zero bytes only, the data is already a plain text
	if (nonzero_key == 0) {
		free(key->data);
		key->data = NULL;
		key->len = 0;
		return 0;
	}

	/*
	   Here we have the key bytes string extracted, but the key itself can be shorter.
	   For example, if the computed key string is "aabaa", we cannot be certain what the
	   real key is. Possible options are: "aab", "aaba", "aabaa".
	   The strategy here is to always choose the shortest possible option. Its length
	   can be determined by computing the period of the extracted string. We calculate
	   the period and truncate the byte string accordingly.
	*/
	size_t p = period(key->data, key->len);
	key->len = p;

	for (i=0; i < input->len; i += p)
		for (j=0; j<p; ++j)
			// align key to the match so that we can start decoding from input->data[0]
			input->data[i+j] ^= key->data[j + p - (offset % p)];

	logmsg(LOG_DEBUG, 1, "xmatch - Data decoded.\n");

	return 0;
}


int xmatch(Attack *a) {
	Attack *va;
	int matches = 0;

	// no data, nothing to do
	if ((a->a_conn.payload.size == 0) || (a->a_conn.payload.data == NULL)) {
		logmsg(LOG_DEBUG, 1, "xmatch - No data received, nothing to decode.\n");
		return 0;
	}

	// we create a new virtual attack and copy the data as it will be modified if a match is found
	if (((va = calloc(1, sizeof(Attack))) == NULL) ||
	    ((va->a_conn.payload.data = malloc(a->a_conn.payload.size)) == NULL)) {
		logmsg(LOG_ERR, 1, "xmatch error - Unable to allocate memory: %s.\n", strerror(errno));
		return -1;
	}
	memcpy(va->a_conn.payload.data, a->a_conn.payload.data, a->a_conn.payload.size);
	va->virtual = 1;
	va->a_conn.payload.size = a->a_conn.payload.size;

	// perform pattern matching
	xorkey_t key;
	key.data = NULL;
	key.len = 0;

	// match input against the bfa of transformed patterns
	switch ((matches = xm_match(va->a_conn.payload.data, va->a_conn.payload.size, fsm, maxlen, handle_match, &key, BREAK_ON_FIRST_MATCH))) {
	case -1:
		fprintf(stderr, "Error during pattern matching. Terminating.\n");
		exit(EXIT_FAILURE);
	case 0:
		logmsg(LOG_DEBUG, 1, "xmatch - No pattern matches found.\n");
		break;
	default:
		logmsg(LOG_INFO, 1, "xmatch - %d pattern match(es) found.\n", matches);
	}

	// key.len is set to 0 by the callback function if a key consists only of 0-bytes (i.e. null encryption)
	if (matches && key.len) {
		// match(es) found
		logmsg(LOG_DEBUG, 1, "xmatch - Processing decoded attack.\n");

		plughook_process_attack(funclist_attack_analyze, va);

		// assign possible downloads to the original attack,
		// this must happen before PPRIO_SAVE plugins are called
		reassign_downloads(a, va);

		plughook_process_attack(funclist_attack_postproc, va);

		del_attack(va);
	}
	if (key.data) free(key.data);

	return 0;
}

void plugin_register_hooks(void) {
	logmsg(LOG_DEBUG, 1, "    Plugin %s: Registering hooks.\n", module_name);
	add_attack_func_to_list(PPRIO_PREPROC, module_name, "xmatch", (void *) xmatch);

	return;
}

conf_node *plugin_process_confopts(conf_node *tree, conf_node *node, void *opt_data) {
	char		*value = NULL;
	conf_node	*confopt = NULL;

	if ((confopt = check_keyword(tree, node->keyword)) == NULL) return(NULL);

	while (node->val) {
		if ((value = calloc(node->val->size+1, 1)) == NULL) {
			perror("  Error - Unable to allocate memory");
			exit(EXIT_FAILURE);
		}
		memcpy(value, node->val->data, node->val->size);

		node->val = node->val->next;

		if OPT_IS("xpattern_file") {
			xpattern_file = value;
		} else {
			fprintf(stderr, "  Error - Invalid configuration option for plugin %s: %s\n", module_name, node->keyword);
			exit(EXIT_FAILURE);
		}
	}
	return(node);
}

void plugin_config(void) {
	register_plugin_confopts(module_name, config_keywords, sizeof(config_keywords)/sizeof(char *));
	if (process_conftree(config_tree, config_tree, plugin_process_confopts, NULL) == NULL) {
		fprintf(stderr, "  Error - Unable to process configuration tree for plugin %s.\n", module_name);
		exit(EXIT_FAILURE);
	}
	return;
}

void plugin_init(void) {
	FILE *pfile = NULL;
	u_char hexbyte, *pattern;
	size_t len, i;
	int rv;

	// read patterns and build pattern matching fsm
	if (!xpattern_file) {
		fprintf(stderr, "  Error - No pattern filename given.\n");
		exit(EXIT_FAILURE);
	}

	if ((pfile = fopen(xpattern_file, "r")) == NULL) {
		fprintf(stderr, "  Error - Could not open pattern file: %s.\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	while (!feof(pfile)) {
		switch (fscanf(pfile, "%a[^\n]\n", &pattern)) {
		case -1:
			fprintf(stderr, "  Error - Unable to process pattern file: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		case 1:
			// skip comments
			if (pattern[0] == '#') {
				free(pattern);
				break;
			}

			// convert hex string to binary
			errno = 0;
			for (len = 0; ; ++len) {
				if ((rv = sscanf((char *) pattern + (len * 4), "\\x%02x", (unsigned int *) &hexbyte)) == EOF) break;
				switch (rv) {
				case -1:
					fprintf(stderr, "  Error - Unable to process pattern file: %s\n", strerror(errno));
					exit(EXIT_FAILURE);
					break;
				case 0:
					fprintf(stderr, "  Error - Malformed line in pattern file: '%s'\n", pattern);
					exit(EXIT_FAILURE);
				default:
					pattern[len] = hexbyte;
					break;
				}
			}

			// for each pattern: calculate matching patterns p' where byte m \in [1:n-1] == p[1] XOR p[m+|keylen|]
			// possible values for keylen are 1..|pattern|/2
			for (i=1; i <= len/2; ++i) {
				if ((p = realloc(p, (num_patterns + 1) * sizeof(xm_string_t *))) == NULL) {
					perror("realloc()");
					exit(EXIT_FAILURE);
				}
				if ((p[num_patterns] = xm_convert(pattern, len, i)) == NULL) {
					perror("xm_convert()");
					exit(EXIT_FAILURE);
				}
				++num_patterns;
			}

			// determine maximum pattern length, keys up to the length of the longest pattern -1 can be found
			if (maxlen < len) maxlen = len;

			break;
		default:
			fprintf(stderr, "Error while reading patterns from file.\n");
			exit(EXIT_FAILURE);
		}
	}
	fclose(pfile);

	// create an fsm for the pattern list
	if ((fsm = xm_fsm_new(p, num_patterns)) == NULL) {
		fprintf(stderr, "Error while building the pattern matching state machine.\n");
		exit(EXIT_FAILURE);
	}

	plugin_register_hooks();

	return;
}

void plugin_unload(void) {
	unhook(PPRIO_PREPROC, module_name, "xmatch");

	// delete the fsm
	xm_fsm_free(fsm);

	// free pattern list
	while (num_patterns) {
		--num_patterns;
		if (p[num_patterns]) {
			if (p[num_patterns]->xdata) free(p[num_patterns]->xdata);
			free(p[num_patterns]);
		}
	}
	free(p);

	return;
}
