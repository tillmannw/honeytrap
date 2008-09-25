/* parseconf.c
 * Copyright (C) 2007 Tillmann Werner <tillmann.werner@gmx.de>
 *
 * This file is free software; as a special exception the author gives
 * unlimited permission to copy and/or distribute it, with or without
 * modifications, as long as this notice is preserved.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
 * implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * The config file parser is based on lcfg from Paul Baecher.
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "parseconf.h"
#include "readconf.h"
#include "logging.h"


struct lcfg_scanner *    lcfg_scanner_new(struct lcfg *, int fd);
enum lcfg_status         lcfg_scanner_init(struct lcfg_scanner *);
enum lcfg_status         lcfg_scanner_next_token(struct lcfg_scanner *, struct lcfg_token *);
int                      lcfg_scanner_has_next(struct lcfg_scanner *);
void                     lcfg_scanner_delete(struct lcfg_scanner *);

struct lcfg_parser *  lcfg_parser_new(struct lcfg *, const char *);
enum lcfg_status      lcfg_parser_run(struct lcfg_parser *);
enum lcfg_status      lcfg_parser_accept(struct lcfg_parser *, lcfg_visitor_function, void *);
void                  lcfg_parser_delete(struct lcfg_parser *);


int lcfg_string_set(struct lcfg_string *s, const char *cstr) {
	lcfg_string_trunc(s, 0);
	return lcfg_string_cat_cstr(s, cstr);
}


/* make sure new_size bytes fit into the string */
inline static void lcfg_string_grow(struct lcfg_string *s, unsigned int new_size) {
	/* always allocate one byte more than needed
	 * to make _cstr() working in any case without realloc. */
	while( (new_size + 1) > s->capacity ) {
		s->capacity *= 2;
		s->str = realloc(s->str, s->capacity);
	}
}

struct lcfg_string *lcfg_string_new() {
	struct lcfg_string *s = malloc(sizeof(struct lcfg_string));
	
	s->capacity = 8;
	s->size = 0;
	s->str = malloc(s->capacity);
	
	return s;
}

struct lcfg_string *lcfg_string_new_copy(struct lcfg_string *s) {
	struct lcfg_string *s_new = malloc(sizeof(struct lcfg_string));
	
	s_new->capacity = s->capacity;
	s_new->size = s->size;
	s_new->str = malloc(s_new->capacity);
	
	memcpy(s_new->str, s->str, s_new->size);
	
	return s_new;
}

int lcfg_string_cat_uint(struct lcfg_string *s, unsigned int i) {
	unsigned int size_needed = 1;
	unsigned int ii = i;
	char c;
	
	while( ii > 10 ) {
		size_needed++;
		ii /= 10;
	}
	
	lcfg_string_grow(s, s->size + size_needed);
	
	ii = size_needed - 1;
	do {
		c = '0' + i % 10;
		s->str[s->size + ii--] = c;
		i /= 10;
	} while( i != 0 );
	
	s->size += size_needed;
	
	return s->size;
}

int lcfg_string_find(struct lcfg_string *s, char c) {
	int i;
	
	for( i = 0; i < s->size; i++ ) if( s->str[i] == c ) return i;
	
	return -1;
}

int lcfg_string_rfind(struct lcfg_string *s, char c) {
	int i;
	
	for( i = s->size - 1; i >= 0; i-- ) if( s->str[i] == c ) return i;
	
	return -1;
}

void lcfg_string_trunc(struct lcfg_string *s, unsigned int max_size) {
	if( max_size < s->size ) s->size = max_size;
}

int lcfg_string_cat_cstr(struct lcfg_string *s, const char *cstr) {
	size_t len = strlen(cstr);
	
	lcfg_string_grow(s, s->size + len);
	
	memcpy(s->str + s->size, cstr, len);
	
	s->size += len;
	
	return s->size;
}

int lcfg_string_cat_char(struct lcfg_string *s, char c) {
	lcfg_string_grow(s, s->size + 1);
	
	s->str[s->size++] = c;
	
	return s->size;
}

inline const char *lcfg_string_cstr(struct lcfg_string *s) {
	s->str[s->size] = '\0';
	return s->str;
}

inline unsigned int lcfg_string_len(struct lcfg_string *s) {
	return s->size;
}

void lcfg_string_delete(struct lcfg_string *s) {
	free(s->str);
	free(s);
}

const char *lcfg_token_map[] = {
	"null_token",
	"T_IDENTIFIER",
	"`='",
	"T_STRING",
	"`['",
	"`]'",
	"`,'",
	"`{'",
	"`}'"
};

struct lcfg_scanner {
	struct lcfg *lcfg;
	
	int fd;
	char buffer[LCFG_BUFSIZ];
	int offset;
	int size;
	int eof;
	
	short line;
	short col;
	
	struct lcfg_token prepared_token;
	int token_eof;
};


static enum lcfg_status lcfg_scanner_buffer_fill(struct lcfg_scanner *s) {
	if( (s->size = read(s->fd, s->buffer, LCFG_BUFSIZ)) < 0 ) {
		lcfg_error_set(s->lcfg, "read(): %m");
		return lcfg_status_error;
	} else if( s->size == 0 ) s->eof = !0;
	else s->offset = 0;
	
	return lcfg_status_ok;
}

static inline int lcfg_scanner_char_eof(struct lcfg_scanner *s) {
	if( s->eof ) return !0;

	if( s->size == 0 || s->offset == LCFG_BUFSIZ) lcfg_scanner_buffer_fill(s);
	if( s->size < LCFG_BUFSIZ && s->offset == s->size ) s->eof = !0;

	return s->eof;
}

static enum lcfg_status lcfg_scanner_char_read(struct lcfg_scanner *s, char *c) {
	if( lcfg_scanner_char_eof(s) ) {
		lcfg_error_set(s->lcfg, "%s", "cannot read beyond eof");
		return lcfg_status_error;
	}
	
	*c = s->buffer[s->offset++];

	return lcfg_status_ok;
}

static enum lcfg_status lcfg_scanner_char_peek(struct lcfg_scanner *s, char *c) {
	if( lcfg_scanner_char_eof(s) ) {
		lcfg_error_set(s->lcfg, "%s", "cannot peek beyond eof");
		return lcfg_status_error;
	}
	
	*c = s->buffer[s->offset];

	return lcfg_status_ok;
}

/* the beautiful lowlevel fsm */
static enum lcfg_status lcfg_scanner_token_read(struct lcfg_scanner *s) {
	enum scanner_state {
		start = 0,
		comm_start,
		in_oneline,
		in_multiline,
		multiline_end,
		in_identifier,
		in_str,
		in_esc,
		esc_hex_exp_first,
		esc_hex_exp_second,
		invalid
	};
	enum scanner_state state = start;
	char c = '\0';
	char hex[3];
	
	s->prepared_token.type = lcfg_null_token;
	
	while( !lcfg_scanner_char_eof(s) ) {
		int consume = !0;
		lcfg_scanner_char_peek(s, &c);
		
		switch( state ) {
		case start:
			switch( c ) {
			case ' ':
			case '\t':
			case '\r':
			case '\n':
				break;
			case '=':
				s->prepared_token.type = lcfg_equals;
				break;
			case '[':
				s->prepared_token.type = lcfg_sbracket_open;
				break;
			case ']':
				s->prepared_token.type = lcfg_sbracket_close;
				break;
			case '{':
				s->prepared_token.type = lcfg_brace_open;
				break;
			case '}':
				s->prepared_token.type = lcfg_brace_close;
				break;
			case ',':
				s->prepared_token.type = lcfg_comma;
				break;
			case '/':
				state = comm_start;
				break;
			case '"':
				state = in_str;
				lcfg_string_trunc(s->prepared_token.string, 0);
				break;
			default:
				if( isalpha(c) ) {
					lcfg_string_trunc(s->prepared_token.string, 0);
					lcfg_string_cat_char(s->prepared_token.string, c);
					state = in_identifier;
				} else {
					lcfg_error_set(s->lcfg, "parse error: invalid input character `%c' (0x%02x) near line %d, col %d",
						isprint(c) ? c : '.', c, s->line, s->col);
					state = invalid;
				}
			}
			break;
		case comm_start:
			if( c == '/' ) state = in_oneline;
			else if( c == '*' ) state = in_multiline;
			else {
				lcfg_error_set(s->lcfg, "parse error: invalid input character `%c' (0x%02x) near line %d, col %d",
					isprint(c) ? c : '.', c, s->line, s->col);
				state = invalid;
			}
			break;
		case in_oneline:
			if( c == '\n' ) state = start;
			break;
		case in_multiline:
			if( c == '*' ) state = multiline_end;
			break;
		case multiline_end:
			if( c == '/' ) state = start;
			else if( c != '*' ) state = in_multiline;
			break;
		case in_identifier:
			if( isalnum(c) || c == '-' || c == '_' ) lcfg_string_cat_char(s->prepared_token.string, c);
			else {
				s->prepared_token.type = lcfg_identifier;
				consume = 0;
				state = start;
			}
			break;
		case in_str:
			if( c == '"' ) {
				s->prepared_token.type = lcfg_string;
				state = start;
			} else if( c == '\\' ) {
				state = in_esc;
			} else {
				lcfg_string_cat_char(s->prepared_token.string, c);
			}
			break;
		case in_esc:
			state = in_str;
			switch( c ) {
			case '"':
				lcfg_string_cat_char(s->prepared_token.string, '"');
				break;
			case '\\':
				lcfg_string_cat_char(s->prepared_token.string, '\\');
				break;
			case 'n':
				lcfg_string_cat_char(s->prepared_token.string, '\n');
				break;
			case 't':
				lcfg_string_cat_char(s->prepared_token.string, '\t');
				break;
			case 'r':
				lcfg_string_cat_char(s->prepared_token.string, '\r');
				break;
			case '0':
				lcfg_string_cat_char(s->prepared_token.string, '\0');
				break;
			case 'x':
				state = esc_hex_exp_first;
				break;
			default:
				lcfg_error_set(s->lcfg, "invalid string escape sequence `%c' near line %d, col %d", c, s->line, s->col);
				state = invalid;
			}
			break;
		case esc_hex_exp_first:
			if( !isxdigit(c) ) {
				lcfg_error_set(s->lcfg, "invalid hex escape sequence `%c' on line %d column %d", c, s->line, s->col);
				state = invalid;
			}
			hex[0] = c;
			state = esc_hex_exp_second;
			break;
		case esc_hex_exp_second:
			if( !isxdigit(c) ) {
				lcfg_error_set(s->lcfg, "invalid hex escape sequence `%c' on line %d column %d", c, s->line, s->col);
				state = invalid;
			}
			hex[1] = c;
			hex[2] = '\0';
			lcfg_string_cat_char(s->prepared_token.string, strtoul(hex, NULL, 16));
			state = in_str;
			break;
		case invalid:
			break;
		}
		
		/* this is technically not optimal (token position identified by last char), but it will suffice for now */
		s->prepared_token.line = s->line;
		s->prepared_token.col = s->col;
	
		if( consume ) {
			lcfg_scanner_char_read(s, &c);
			if( c == '\n' ) {
				s->line++;
				s->col = 1;
			} else s->col++;
		}
		
		if( s->prepared_token.type != lcfg_null_token || state == invalid ) break;
	}
	
	if( state != start ) {
		if( state != invalid ) lcfg_error_set(s->lcfg, "parse error: premature end of file near line %d, col %d", s->line, s->col);
		
		return lcfg_status_error;
	}
	
	return lcfg_status_ok;
}

enum lcfg_status lcfg_scanner_init(struct lcfg_scanner *s) {
	/* prepare the first token */
	return lcfg_scanner_token_read(s); 
}

int lcfg_scanner_has_next(struct lcfg_scanner *s) {
	return s->prepared_token.type != lcfg_null_token;
}

enum lcfg_status lcfg_scanner_next_token(struct lcfg_scanner *s, struct lcfg_token *t) {
	if( !lcfg_scanner_has_next(s) ) {
		lcfg_error_set(s->lcfg, "%s", "cannot access tokenstream beyond eof");
		return lcfg_status_error;
	}
	
	memcpy(t, &s->prepared_token, sizeof(struct lcfg_token));
	t->string = lcfg_string_new_copy(s->prepared_token.string);
	
	/* prepare the next token */
	return lcfg_scanner_token_read(s); 
}

struct lcfg_scanner *lcfg_scanner_new(struct lcfg *c, int fd) {
	struct lcfg_scanner *s = malloc(sizeof(struct lcfg_scanner));
	
	memset(s, 0, sizeof(struct lcfg_scanner));
	
	s->lcfg = c;
	s->fd = fd;
	
	s->line = s->col = 1;
	
	s->prepared_token.string = lcfg_string_new();
	
	return s;
}

void lcfg_scanner_delete(struct lcfg_scanner *s) {
	lcfg_string_delete(s->prepared_token.string);
	free(s);
}

struct lcfg_parser_value_pair {
	char *key;
	struct lcfg_string *value;
};


struct lcfg_parser {
	struct lcfg *lcfg;
	char *filename;
	struct lcfg_scanner *scanner;
	
	struct lcfg_parser_value_pair *values;
	unsigned int value_length;
	unsigned int value_capacity;
};

static int lcfg_parser_add_value(struct lcfg_parser *p, const char *key, struct lcfg_string *value) {
	if( p->value_length == p->value_capacity ) {
		p->value_capacity *= 2;
		p->values = realloc(p->values, sizeof(struct lcfg_parser_value_pair) * p->value_capacity);
	}
	
	p->values[p->value_length].key = strdup(key);
	p->values[p->value_length].value = lcfg_string_new_copy(value);
	
	return ++p->value_length;
}

struct lcfg_parser *lcfg_parser_new(struct lcfg *c, const char *filename) {
	struct lcfg_parser *p = malloc(sizeof(struct lcfg_parser));
	
	memset(p, 0, sizeof(struct lcfg_parser));
	
	p->filename = strdup(filename);
	p->lcfg = c;
	
	p->value_length = 0;
	p->value_capacity = 8;
	p->values = malloc(sizeof(struct lcfg_parser_value_pair) * p->value_capacity);
	
	return p;
}

/* this is a basic push down automata */
static enum lcfg_status lcfg_parser_parse(struct lcfg_parser *p) {
	enum state { top_level = 0, exp_equals, exp_value, in_list, in_map, invalid };
	/*const char *state_map[] = { "top_level", "exp_equals", "exp_value", "in_list", "in_map", "invalid" };*/

	struct state_element {
		enum state s;
		int list_counter;
	};

	/* start of ugly preproc stuff */
	#define STATE_STACK_PUSH(t) \
	if( ssi + 1 == state_stack_size ) \
	{ \
		state_stack_size *= 2; \
		state_stack = realloc(state_stack, state_stack_size * sizeof(struct state_element)); \
	} \
	state_stack[++ssi].s = t; \
	state_stack[ssi].list_counter = 0
	#define STATE_STACK_POP() ssi--
	#define PATH_PUSH_STR(s) \
	if( lcfg_string_len(current_path) != 0 ) \
	{ \
		lcfg_string_cat_char(current_path, '.'); \
	} \
	lcfg_string_cat_cstr(current_path, s);
	#define PATH_PUSH_INT(i) \
	if( lcfg_string_len(current_path) != 0 ) \
	{ \
		lcfg_string_cat_char(current_path, '.'); \
	} \
	lcfg_string_cat_uint(current_path, i);
	#define PATH_POP() \
	if( lcfg_string_rfind(current_path, '.') != -1 ) \
	{ \
		lcfg_string_trunc(current_path, lcfg_string_rfind(current_path, '.')); \
	} \
	else \
	{ \
		lcfg_string_trunc(current_path, 0); \
	}
	/* end of ugly preproc stuff */

	if( lcfg_scanner_init(p->scanner) != lcfg_status_ok ) return lcfg_status_error;
	
	int state_stack_size = 8;
	int ssi = 0; /* ssi = state stack index */
	struct state_element *state_stack = malloc(sizeof(struct state_element) * state_stack_size);
	
	state_stack[ssi].s = top_level;
	state_stack[ssi].list_counter = 0;
	
	struct lcfg_token t;
	struct lcfg_string *current_path = lcfg_string_new();
	
	while( lcfg_scanner_has_next(p->scanner) && state_stack[ssi].s != invalid ) {
		if( lcfg_scanner_next_token(p->scanner, &t) != lcfg_status_ok ) {
			free(state_stack);
			lcfg_string_delete(t.string);
			lcfg_string_delete(current_path);
			return lcfg_status_error;
		}
		
		switch( state_stack[ssi].s ) {
		case top_level:
		case in_map:
			if( t.type == lcfg_identifier ) {
				PATH_PUSH_STR(lcfg_string_cstr(t.string));
				STATE_STACK_PUSH(exp_equals);
			} else if( state_stack[ssi].s == in_map && t.type == lcfg_brace_close ) {
				STATE_STACK_POP();
				PATH_POP();
			} else {
				lcfg_error_set(p->lcfg, "invalid token (%s) near line %d column %d: expected identifier%s",
					lcfg_token_map[t.type], t.line, t.col, state_stack[ssi].s == in_map ? " or `}'" : ""); 
				state_stack[ssi].s = invalid;
			}
			break;
		case exp_equals:
			if( t.type == lcfg_equals ) state_stack[ssi].s = exp_value;
			else {
				lcfg_error_set(p->lcfg, "invalid token (%s) near line %d column %d: expected `='",
					lcfg_token_map[t.type], t.line, t.col); 
				state_stack[ssi].s = invalid;
			}
			break;
		case exp_value:
			if( t.type == lcfg_string ) {
				lcfg_parser_add_value(p, lcfg_string_cstr(current_path), t.string);
				STATE_STACK_POP();
				PATH_POP();
			} else if( t.type == lcfg_sbracket_open ) state_stack[ssi].s = in_list;
			else if( t.type == lcfg_brace_open ) state_stack[ssi].s = in_map;
			else {
				lcfg_error_set(p->lcfg, "invalid token (%s) near line %d column %d: expected string, `[' or `{'",
					lcfg_token_map[t.type], t.line, t.col); 
				state_stack[ssi].s = invalid;
			}
			break;
		case in_list:
			if( t.type == lcfg_comma ); /* ignore comma */
			else if( t.type == lcfg_string ) {
				PATH_PUSH_INT(state_stack[ssi].list_counter);
				lcfg_parser_add_value(p, lcfg_string_cstr(current_path), t.string);
				PATH_POP();
				state_stack[ssi].list_counter++;
			} else if( t.type == lcfg_sbracket_open ) {
				PATH_PUSH_INT(state_stack[ssi].list_counter);
				state_stack[ssi].list_counter++;
				STATE_STACK_PUSH(in_list);
			} else if( t.type == lcfg_brace_open ) {
				PATH_PUSH_INT(state_stack[ssi].list_counter);
				state_stack[ssi].list_counter++;
				STATE_STACK_PUSH(in_map);
			} else if( t.type == lcfg_sbracket_close ) {
				PATH_POP();
				STATE_STACK_POP();
			} else {
				lcfg_error_set(p->lcfg, "invalid token (%s) near line %d column %d: expected string, `[', `{', `,' or `]'",
					lcfg_token_map[t.type], t.line, t.col); 
				state_stack[ssi].s = invalid;
			}
			break;
		case invalid: /* unreachable */
			break;
		}
		
		lcfg_string_delete(t.string);
	}

	lcfg_string_delete(current_path);	
	
	if( state_stack[ssi].s == top_level && ssi == 0 ) {
		free(state_stack);
		return lcfg_status_ok;
	} else {
		free(state_stack);
		return lcfg_status_error;
	}
}

enum lcfg_status lcfg_parser_run(struct lcfg_parser *p) {	
	int fd = open(p->filename, 0);
	enum lcfg_status status;
	
	if( fd < 0 ) {
		lcfg_error_set(p->lcfg, "open(): %m");
		return lcfg_status_error;
	}
	
	p->scanner = lcfg_scanner_new(p->lcfg, fd);
	
	status = lcfg_parser_parse(p);	
	
	close(fd);
	
	return status;
}

enum lcfg_status lcfg_parser_accept(struct lcfg_parser *p, lcfg_visitor_function fn, void *user_data) {
	int i;
	
	for( i = 0; i < p->value_length; i++ ) {
		if( fn(p->values[i].key, (void *)lcfg_string_cstr(p->values[i].value),
			lcfg_string_len(p->values[i].value), user_data) != lcfg_status_ok ) {
			lcfg_error_set(p->lcfg, "%s", "configuration value traversal aborted upon user request");
			return lcfg_status_error;
		}
	}
	
	return lcfg_status_ok;
}

void lcfg_parser_delete(struct lcfg_parser *p) {
	if (p->scanner) lcfg_scanner_delete(p->scanner);
	
	int i;
	
	for( i = 0; i < p->value_length; i++ ) {
		free(p->values[i].key);
		lcfg_string_delete(p->values[i].value);
	}
	free(p->values);
	free(p->filename);
	free(p);
}

struct lcfg *lcfg_new(const char *filename) {
	struct lcfg *c = malloc(sizeof(struct lcfg));
	memset(c, 0, sizeof(struct lcfg));
	
	c->parser = lcfg_parser_new(c, filename);
	
	return c;
}

void lcfg_delete(struct lcfg *c) {
	if (c->parser) lcfg_parser_delete(c->parser);
	free(c);
}

const char *lcfg_error_get(struct lcfg *c) {
	return c->error;
}

enum lcfg_status lcfg_parse(struct lcfg *c) {
	return lcfg_parser_run(c->parser);
}

enum lcfg_status lcfg_accept(struct lcfg *c, lcfg_visitor_function fn, void *user_data) {
	return lcfg_parser_accept(c->parser, fn, user_data);
}

void lcfg_error_set(struct lcfg *c, const char *fmt, ...) {	
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(c->error, sizeof(c->error), fmt, ap);
	va_end(ap);
}

struct lcfg *parse_config_file(const char *filename) {
	struct lcfg *c = NULL;

	if (!filename) {
		fprintf(stderr, "  Error - No configuration file name given.\n");
		return(NULL);
	}

	/* parse file */
	c = lcfg_new(filename);
	if (lcfg_parse(c) != lcfg_status_ok) {
		fprintf(stderr, "  Error -  Unable to parse %s: %s\n", filename, lcfg_error_get(c));
		lcfg_delete(c);	
		return(NULL);
	}
	
	return(c);
}
