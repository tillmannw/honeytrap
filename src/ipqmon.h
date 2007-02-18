/* ipqmon.h
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

#ifdef USE_IPQ_MON

#ifndef __HONEYTRAP_IPQMON_H
#define __HONEYTRAP_IPQMON_H 1

#include <libipq.h>
#include <linux/netfilter.h>

struct ipq_handle *h;
ipq_packet_msg_t *packet;

int start_ipq_mon(void);

#endif

#endif
