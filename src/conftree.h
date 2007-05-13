/* conftree.h
 * Copyright (C) 2007 Tillmann Werner <tillmann.werner@gmx.de>
 *
 * This file is free software; as a special exception the author gives
 * unlimited permission to copy and/or distribute it, with or without
 * modifications, as long as this notice is preserved.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
 * implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */

#ifndef __HONEYTRAP_CONFTREE_H
#define __HONEYTRAP_CONFTREE_H 1

/* config file keyword configuration goes herei
 * don't forget to adjust the number */


typedef struct conf_node {
	char 			*keyword;
	struct conf_node	*first_leaf;
	struct conf_node	*next;
} conf_node;


conf_node *config_keywords_tree;


void print_conftree(conf_node *tree, int depth);
conf_node *check_keyword(conf_node *tree, const char *keyword);
conf_node *add_keyword(conf_node **tree, const char *keyword);

#endif
