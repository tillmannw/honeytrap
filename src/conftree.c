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


void print_conftree(conf_node *tree, int depth) {
	int i;
	conf_node *cur_node;

	cur_node = tree;
	while(cur_node) {
		if (cur_node->keyword) {
			for (i=0; i<depth*2; i++) printf(" ");
			printf("%s\n", cur_node->keyword);
		}
		print_conftree(cur_node->first_leaf, depth+1);
		cur_node = cur_node->next;
	}
	return;
}


/* check whether (the prefix of) a keyword does exist in the tree *
 * and return a pointer to the node containing its last part */
conf_node *check_keyword(conf_node *tree, const char *keyword) {
	conf_node	*cur_node;
	char		*key, *subkey;

	if (!tree) return(NULL);
	if (!keyword) {
		logmsg(LOG_WARN, 1, "Error - Unable to search tree: No keyword given.\n");
		return(NULL);
	}

	cur_node	= tree;

	if ((key = strdup(keyword)) ==  NULL) {
		logmsg(LOG_ERR, 1, "Error - Unable to allocate memory: %s.\n", strerror(errno));
		return(NULL);
	}

	if ((subkey = strchr(key, '.')) != NULL) {
		subkey[0] = 0;
		subkey++;
	}

	/* depth first search in config tree */
	while(cur_node) {
		if (strncmp(cur_node->keyword, keyword, strlen(keyword)) == 0) {
			free(key);
			return(cur_node);
		}
		if (subkey) {
			if (strncmp(cur_node->keyword, key, strlen(key)) == 0) {
				tree = cur_node->first_leaf;
				while (tree) {
					cur_node = check_keyword(tree, subkey);
					if (cur_node) return(cur_node);
					tree = tree->next;
				}
				break;
			}
		}
		cur_node = cur_node->next;
	}

	free(key);
	return(NULL);
}


/* insert new node into config tree and return a pointer to it
 * if *tree is NULL, it will be set to point to the root node */
conf_node *add_keyword(conf_node **tree, const char *keyword) {
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

	/* check whether the keyword or a prefix of it does already exist */
	if ((cur_node = check_keyword(*tree, keyword)) == NULL) {
		if ((key = strdup(keyword)) ==  NULL) {
			logmsg(LOG_ERR, 1, "Error - Unable to allocate memory: %s.\n", strerror(errno));
			return(NULL);
		}
		if ((subkey = strrchr(key, '.')) != NULL) {
			subkey[0] = 0;		// zero-terminate first half
			subkey++;		// pointer to second half
			cur_node = add_keyword(tree, key);
		} else subkey = key;
	} else return(cur_node);		// node already exists


	/* create new node and insert it into tree */
	if ((new_node = malloc(sizeof(conf_node))) == NULL) {
		logmsg(LOG_ERR, 1, "Error - Unable to allocate memory: %s.\n", strerror(errno));
		free(key);
		return(NULL);
	}
	memset(new_node, 0, sizeof(conf_node));
	if ((new_node->keyword = strdup(subkey)) == NULL) {
		logmsg(LOG_ERR, 1, "Error - Unable to allocate memory: %s.\n", strerror(errno));
		free(key);
		return(NULL);
	}
	free(key);

	/* insert new node into tree */
	if (cur_node) {
		/* it's an internal node */
		if (cur_node->first_leaf) {
			cur_node = cur_node->first_leaf;
			while (cur_node->next) cur_node = cur_node->next;
			cur_node->next = new_node;
		} else cur_node->first_leaf = new_node;
	} else {
		/* it's the root node */
		if (!(*tree)) (*tree) = new_node;
		/* it's a root's neighbor */
		else {
			cur_node = *tree;
			while (cur_node->next) cur_node = cur_node->next;
			cur_node->next = new_node;
		}
	}

	return(new_node);
}
