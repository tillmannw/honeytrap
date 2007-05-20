/* parseconf.h
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

#ifndef __HONEYTRAP_PARSECONF_H
#define __HONEYTRAP_PARSECONF_H 1


#define LCFG_BUFSIZ 0xff

struct lcfg {
	char error[LCFG_BUFSIZ];
	struct lcfg_parser *parser;
};

enum lcfg_status {
	lcfg_status_ok,
	lcfg_status_error
};

typedef enum lcfg_status (* lcfg_visitor_function) (const char *key, void *data, size_t size, void *user_data);

enum lcfg_token_type {
	lcfg_null_token = 0,
	lcfg_identifier,
	lcfg_equals,
	lcfg_string,
	lcfg_sbracket_open,
	lcfg_sbracket_close,
	lcfg_comma,
	lcfg_brace_open,
	lcfg_brace_close
};

extern const char *lcfg_token_map[];

struct lcfg_token {
	enum lcfg_token_type type;
	struct lcfg_string *string;
	short line;
	short col;
};

struct lcfg_string {
	char *str;
	unsigned int size;
	unsigned int capacity;
};

struct lcfg_string *lcfg_string_new();
struct lcfg_string *lcfg_string_new_copy(struct lcfg_string *);
int lcfg_string_set(struct lcfg_string *, const char *);
int lcfg_string_cat_char(struct lcfg_string *, char);
int lcfg_string_cat_cstr(struct lcfg_string *, const char *);
int lcfg_string_cat_uint(struct lcfg_string *, unsigned int);
int lcfg_string_find(struct lcfg_string *, char);
int lcfg_string_rfind(struct lcfg_string *, char);
void lcfg_string_trunc(struct lcfg_string *, unsigned int);
inline const char *lcfg_string_cstr(struct lcfg_string *);
inline unsigned int lcfg_string_len(struct lcfg_string *);
void lcfg_string_delete(struct lcfg_string *);
void lcfg_error_set(struct lcfg *c, const char *fmt, ...);
enum lcfg_status lcfg_accept(struct lcfg *c, lcfg_visitor_function fn, void *user_data);
void lcfg_delete(struct lcfg *c);
struct lcfg *parse_config_file(const char *filename);

#endif
