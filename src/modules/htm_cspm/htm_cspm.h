/* htm_CSPM.h
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
 *
 * Idea taken from CSPM snort plugin by Markus Koetter and Paul Baecher
 */

#ifndef __HT_MODULE_CSPM_H
#define __HT_MODULE_CSPM_H 1

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdint.h>
#include <pcre.h>


enum sc_namespace { 
	sc_xor,
	sc_linkxor,
	sc_konstanzxor,
	sc_leimbachxor,
	sc_connectbackshell,
	sc_connectbackfiletransfer,
	sc_bindshell,
	sc_execute,
	sc_download,
	sc_url,
	sc_bindfiletransfer,
	sc_base64,
	sc_alphanumericxor
};

enum sc_mapping { 
	sc_key,
	sc_subkey,
	sc_size, 
	sc_sizeinvert, 
	sc_port, 
	sc_host,
	sc_command,
	sc_uri,
	sc_decoder,
	sc_pre,
	sc_post,
	sc_none,
	sc_hostkey,
	sc_portkey,
	sc_payload
};

#define MAP_MAX 8
struct sc_shellcode {
	pcre *compiled_pattern;

	char *name;
	char *author;
	char *reference;
	char *pattern;
	int pattern_size;
	enum sc_namespace nspace;
	int map_items;
	enum sc_mapping map[MAP_MAX];
	int flags;

	struct sc_shellcode *next;
};

typedef enum {
	SCH_NOTHING=0,
	SCH_REPROCESS,	// if something was changes f.e. xor decoder
	SCH_REPROCESS_BUT_NOT_ME,
	SCH_DONE,
} sch_result;

int prepare_sc(struct sc_shellcode *sc);

sch_result eval_sc_mgr(void *data, uint32_t size, uint32_t remotehost, uint16_t remoteport, uint32_t localhost, uint16_t localport);

sch_result eval_sc			(struct sc_shellcode *nsch, void **data, uint32_t *size, uint32_t remotehost, uint16_t remoteport, uint32_t localhost, uint16_t localport);
sch_result eval_engine_unicode		(struct sc_shellcode *nsch, void **data, uint32_t *size, uint32_t remotehost, uint16_t remoteport, uint32_t localhost, uint16_t localport);
uint32_t eval_engine_unicode_unicodeLength(uint8_t *unicode, uint32_t len);
uint32_t eval_engine_unicode_unicodeTryDecode(uint8_t *unicode, uint32_t len, uint8_t **decoded, uint32_t *decodedLength);
sch_result eval_alphanumericxor         (struct sc_shellcode *nsch, void **data, uint32_t *size, uint32_t remotehost, uint16_t remoteport, uint32_t localhost, uint16_t localport);
sch_result eval_base64                  (struct sc_shellcode *nsch, void **data, uint32_t *size, uint32_t remotehost, uint16_t remoteport, uint32_t localhost, uint16_t localport);
sch_result eval_bindfiletransfer        (struct sc_shellcode *nsch, void **data, uint32_t *size, uint32_t remotehost, uint16_t remoteport, uint32_t localhost, uint16_t localport);
sch_result eval_bindshell               (struct sc_shellcode *nsch, void **data, uint32_t *size, uint32_t remotehost, uint16_t remoteport, uint32_t localhost, uint16_t localport);
sch_result eval_connectbackfiletransfer (struct sc_shellcode *nsch, void **data, uint32_t *size, uint32_t remotehost, uint16_t remoteport, uint32_t localhost, uint16_t localport);
sch_result eval_connectbackshell        (struct sc_shellcode *nsch, void **data, uint32_t *size, uint32_t remotehost, uint16_t remoteport, uint32_t localhost, uint16_t localport);
sch_result eval_execute                 (struct sc_shellcode *nsch, void **data, uint32_t *size, uint32_t remotehost, uint16_t remoteport, uint32_t localhost, uint16_t localport);
sch_result eval_konstanzxor             (struct sc_shellcode *nsch, void **data, uint32_t *size, uint32_t remotehost, uint16_t remoteport, uint32_t localhost, uint16_t localport);
sch_result eval_linkxor                 (struct sc_shellcode *nsch, void **data, uint32_t *size, uint32_t remotehost, uint16_t remoteport, uint32_t localhost, uint16_t localport);
sch_result eval_url                     (struct sc_shellcode *nsch, void **data, uint32_t *size, uint32_t remotehost, uint16_t remoteport, uint32_t localhost, uint16_t localport);
sch_result eval_xor                     (struct sc_shellcode *nsch, void **data, uint32_t *size, uint32_t remotehost, uint16_t remoteport, uint32_t localhost, uint16_t localport);

struct sc_shellcode *sclist;

void plugin_init(void);
void plugin_unload(void);
void plugin_register_hooks(void);
conf_node *plugin_process_confopts(conf_node *tree, conf_node *node, void *opt_data);
int load_shellcodes(void);
int sc_match(Attack *attack);

#endif
