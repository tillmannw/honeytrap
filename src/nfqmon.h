/* nfqmon.h
 * Copyright (C) 2007-2008 Tillmann Werner <tillmann.werner@gmx.de>
 *
 * This file is free software; as a special exception the author gives
 * unlimited permission to copy and/or distribute it, with or without
 * modifications, as long as this notice is preserved.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
 * implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */

#ifdef USE_NFQ_MON

#ifndef __HONEYTRAP_NFQMON_H
#define __HONEYTRAP_NFQMON_H 1

#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

int id;
struct nfq_handle *h;
struct nfq_q_handle *qh;

int start_nfq_mon(void);

#endif

#endif
