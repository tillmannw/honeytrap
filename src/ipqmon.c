/* ipqmon.c
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

#include "honeytrap.h"
#ifdef USE_IPQ_MON

#include <errno.h>
#include <stdlib.h>
#include <linux/netfilter.h>
#include <libipq.h>
#include <errno.h>
#include <string.h>

#include "logging.h"
#include "tcpserver.h"
#include "ctrl.h"
#include "ipqmon.h"

// BUFSIZE >= 256 seem to work for new tcp connections
#define BUFSIZE 256

static void die(struct ipq_handle *h) {
	logmsg(LOG_ERR, 1, "IPQ Error: %s - %s.\n", ipq_errstr(), strerror(errno));
	ipq_destroy_handle(h);
	clean_exit(0);
}

int start_ipq_mon(void) {
	int status;
	unsigned char buf[BUFSIZE];
	struct ipq_handle *h;
	ipq_packet_msg_t *m;
	struct ip_header *ip;
	struct tcp_header *tcp;

	logmsg(LOG_DEBUG, 1, "Creating ipq connection monitor.\n");
	if ((h = ipq_create_handle(0, PF_INET)) == NULL) die(h);

	status = ipq_set_mode(h, IPQ_COPY_PACKET, BUFSIZE);
	if (status < 0) die(h);

	logmsg(LOG_NOTICE, 1, "---- Trapping attacks via IPQ. ----\n");

	for (;;) {
		status = ipq_read(h, buf, BUFSIZE, 0);
		if (status < 0) die(h);

		switch (ipq_message_type(buf)) {
			case NLMSG_ERROR:
				logmsg(LOG_ERR, 1, "IPQ Error: %s\n", strerror(ipq_get_msgerr(buf)));
				break;
			case IPQM_PACKET:
				m = ipq_get_packet(buf);
				ip = (struct ip_header*) m->payload;
				tcp = (struct tcp_header*) (m->payload + (4 * ip->ip_hlen));
				/* Got a connection request, fork handler and pass it back to the kernel */
				logmsg(LOG_INFO, 1, "Connection request on port %d.\n", ntohs(tcp->th_dport));
				start_tcp_server(ip->ip_src, tcp->th_sport, ip->ip_dst, tcp->th_dport);
				if ((status = ipq_set_verdict(h, m->packet_id, NF_ACCEPT, 0, NULL)) < 0) die(h);
				break;
			default:
				logmsg(LOG_DEBUG, 1, "IPQ Warning - Unknown message type!\n");
				break;
		}
	}

	ipq_destroy_handle(h);
	return(1);
}

#endif
