/* pcapmon.h
 * Copyright (C) 2005-2006 Tillmann Werner <tillmann.werner@gmx.de>
 *
 * This file is free software; as a special exception the author gives
 * unlimited permission to copy and/or distribute it, with or without
 * modifications, as long as this notice is preserved.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
 * implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */

#ifdef USE_PCAP_MON

#ifndef __HONEYTRAP_PCAPMON_H
#define __HONEYTRAP_PCAPMON_H 1

#include <pcap.h>
#include <netdb.h>

char *bpf_filter_string;
bpf_u_int32 mask;
bpf_u_int32 net;

pcap_t *packet_sniffer;
u_char pcap_offset;

int start_pcap_mon(void);
char *create_bpf(char *bpf_cmd_ext, struct hostent *ip_cmd_opt, const char *dev);

#endif

#endif
