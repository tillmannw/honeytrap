/* conftree.c
 * Copyright (C) 2006-2007 Tillmann Werner <tillmann.werner@gmx.de>
 *
 * This file is free software; as a special exception the author gives
 * unlimited permission to copy and/or distribute it, with or without
 * modifications, as long as this notice is preserved.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
 * implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */

#include <errno.h>
#include <stdio.h>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <netdb.h>
#include <strings.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/file.h>

#include "honeytrap.h"
#include "logging.h"
#include "conftree.h"


void conftree_children_free(conf_node *tree) {
	conf_node	*cur_node, *old_node;
	list_entry	*val, *old_val;

	if (!tree) return;

	cur_node = tree->first_leaf;
	while (cur_node) {
		if (cur_node->first_leaf) conftree_children_free(cur_node->first_leaf);
		free(cur_node->keyword);
		val = cur_node->val;
		while (val) {
			free(val->data);
			old_val = val;
			val = val->next;
			free(old_val);
		}
		old_node = cur_node;
		cur_node = cur_node->next;
		free(old_node);
	}
	return;
}


void print_conftree(conf_node *tree, int depth) {
	int i;
	char c;
	conf_node	*cur_node;
	list_entry	*val;

	cur_node = tree;
	while(cur_node) {
		if (cur_node->keyword) {
			for (i=0; i<depth*2; i++) printf(" ");
			printf("%s", cur_node->keyword);
			val = cur_node->val;
			while (val) {
				if (val->data) {
					printf("\n\t\t\"");
					for( i = 0; i < val->size; i++ )
						printf("%c", isprint(c = *((const char *)(val->data+i))) ? c : '.');
					printf("\"");
				}
				val = val->next;
			}
			printf("\n");
		}
		print_conftree(cur_node->first_leaf, depth+1);
		cur_node = cur_node->next;
	}
	return;
}


list_entry *add_list_item(conf_node *node, const void *data, ssize_t size) {
	list_entry	*new_entry, *cur_entry;

	if (!node) return(NULL);

	/* create new element */
	if ((new_entry = malloc(sizeof(list_entry))) == NULL) {
		logmsg(LOG_ERR, 1, "Error - Unable to allocate memory: %m.\n");
		return(NULL);
	}
	memset(new_entry, 0, sizeof(list_entry));

	/* copy data */
	if ((new_entry->data = malloc(size+1)) == NULL) {
		logmsg(LOG_ERR, 1, "Error - Unable to allocate memory: %m.\n");
		return(NULL);
	}
	memset(new_entry->data, 0, size+1);
	new_entry->size = size;
	memcpy(new_entry->data, data, size);

	/* attach new element to list tail and return */
	if ((cur_entry = node->val) != NULL) {
		while (cur_entry->next) cur_entry = cur_entry->next;
		cur_entry->next = new_entry;
	} else node->val = new_entry;

	return(new_entry);
}


/* return first leaf node of subtree for given keyword */
conf_node *conf_subtree(conf_node *tree, const char *keyword) {
	conf_node *subtree;

	if ((subtree = check_keyword(tree, keyword)) == NULL) return(NULL);
	return(subtree->first_leaf);
}


/* check whether (the prefix of) a keyword does exist in the tree *
 * and return a pointer to the node containing its last part */
conf_node *check_keyword(conf_node *tree, const char *keyword) {
	conf_node	*cur_node;
	char		**key, *subkey;

	cur_node	= tree;
	subkey		= NULL;

	if (!tree) return(NULL);
	if (!keyword) {
		fprintf(stderr, "  Error - Unable to search tree: No keyword given.\n");
		return(NULL);
	}


	if (((key = (char **) malloc(sizeof(char *))) == NULL) || ((*key = strdup(keyword)) ==  NULL)) {
		fprintf(stderr, "  Error - Unable to allocate memory: %m.\n");
		return(NULL);
	}

	/* search in config tree */
	if ((subkey = strsep(key, ".")) == NULL) {
		free(key);
		return(NULL);
	}
	while (cur_node) {
		/* compare current node's keyword with prefix */
		if (strcmp(cur_node->keyword, subkey) == 0) {
			if ((subkey = strsep(key, ".")) == NULL) return(cur_node);
			cur_node = cur_node->first_leaf;
		} else cur_node = cur_node->next;
	}

	free(key);
	return(NULL);
}


/* insert new node into config tree and return a pointer to it
 * if *tree is NULL, it will be set to point to the root node */
conf_node *add_keyword(conf_node **tree, const char *keyword, const void *data, ssize_t size) {
	conf_node	*new_node, *cur_node;
	char		*key, *subkey;

	cur_node	= *tree;
	new_node	= NULL;
	key		= NULL;
	subkey		= NULL;


	if (!keyword) {
		logmsg(LOG_WARN, 1, "Warning - Unable to extend configuration tree: No keyword given.\n");
		return(*tree);
	}

	// check whether a prefix does already exist and if not, add it recursively
	if ((key = strdup(keyword)) ==  NULL) {
		logmsg(LOG_ERR, 1, "Error - Unable to allocate memory: %m.\n");
		return(NULL);
	}

	/* add recursively */
	if ((cur_node = check_keyword(*tree, key)) == NULL) {
		if ((subkey = strrchr(key, '.')) != NULL) {
			subkey[0] = 0;		// zero-terminate first half
			subkey++;		// pointer to second half
			if (isdigit(subkey[0])) {
				if ((cur_node = check_keyword(*tree, key)) == NULL)
					if ((cur_node = add_keyword(tree, key, NULL, 0)) == NULL) return(NULL);
				if (add_list_item(cur_node, data, size) == NULL) {
					fprintf(stderr, "  Error - Unable to add list item for %s.\n", key);
					return(NULL);
				}
				return(cur_node);
			}
			if ((cur_node = add_keyword(tree, key, NULL, 0)) == NULL) return(NULL);
		}
	} else return(cur_node);

	// create new node and insert it into tree
	if ((new_node = malloc(sizeof(conf_node))) == NULL) {
		logmsg(LOG_ERR, 1, "Error - Unable to allocate memory: %m.\n");
		free(key);
		return(NULL);
	}
	memset(new_node, 0, sizeof(conf_node));
	// if keyword is a toplevel key, add it, else add subkey
	if ((new_node->keyword = strdup(subkey ? subkey : key)) == NULL) {
		logmsg(LOG_ERR, 1, "Error - Unable to allocate memory: %m.\n");
		free(key);
		return(NULL);
	}
	free(key);

	if (size) {
		if (add_list_item(new_node, data, size) == NULL) {
			fprintf(stderr, "  Error - Unable to add list item for %s.\n", keyword);
			return(NULL);
		}
	}

	/* insert new node into tree */
	if (cur_node) {
		/* it's an internal node */
		if (cur_node->first_leaf) {
			cur_node = cur_node->first_leaf;
			while (cur_node->next) cur_node = cur_node->next;
			cur_node->next = new_node;
		} else cur_node->first_leaf = new_node;
	} else {
		/* it's a top level node */
		if (!(*tree)) (*tree) = new_node;
		/* it's a root's neighbor */
		else {
			cur_node = *tree;
			while (cur_node->next) cur_node = cur_node->next;
			cur_node->next = new_node;
		}
	}
	if (*tree == NULL) *tree = cur_node;

	return(new_node);
}
