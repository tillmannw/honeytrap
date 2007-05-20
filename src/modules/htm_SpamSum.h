/* htm_SpamSum.h
 * Copyright (C) 2006 Tillmann Werner <tillmann.werner@gmx.de>
 *
 * This file is free software; as a special exception the author gives
 * unlimited permission to copy and/or distribute it, with or without
 * modifications, as long as this notice is preserved.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
 * implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */

#ifndef __HT_MODULE_SPAMSUM_H
#define __HT_MODULE_SPAMSUM_H 1

#if HAVE_CONFIG_H
# include <config.h>
#endif

void plugin_init(void);
void plugin_unload(void);
void plugin_register_hooks(void);
void plugin_register_confopts(void);
conf_node *plugin_process_confopts(conf_node *tree, conf_node *node, void *opt_data);
int calc_spamsum(Attack *attack);
char *spamsum(const u_char *in, size_t length, u_int32_t bsize);
static inline u_int32_t roll_hash(u_char c);
static u_int32_t roll_reset(void);
static inline u_int32_t sum_hash(u_char c, u_int32_t h);
u_int32_t spamsum_match(const char *str1, const char *str2);
u_int32_t spamsum_match_db(const char *fname, const char *sum, u_int32_t threshold);
static char *eliminate_sequences(const char *str);
static unsigned score_strings(const char *s1, const char *s2, u_int32_t block_size);
static int has_common_substring(const char *s1, const char *s2);
int edit_distn(char *from, register int from_len, char *to, register int to_len);

#endif
