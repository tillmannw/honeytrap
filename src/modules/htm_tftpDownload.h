/* htm_tftpDownload.h
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

#ifndef __HT_MODULE_TFTPDOWNLOAD_H
#define __HT_MODULE_TFTPDOWNLOAD_H 1

#if HAVE_CONFIG_H
# include <config.h>
#endif

void plugin_init(void);
void plugin_unload(void);
void plugin_register_hooks(void);
int cmd_parse_for_tftp(Attack *attack);
int get_tftpcmd(char *attack_string, int string_size, Attack *attack);
int tftp_quit(int data_sock_fd);
int get_tftp_resource(struct in_addr* host, const char *save_file, Attack *attack);

#endif
