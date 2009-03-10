/* ipqmon.c
 * Copyright (C) 2006-2007 Tillmann Werner <tillmann.werner@gmx.de>
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

#include <arpa/inet.h>
#include <errno.h>
#include <libipq.h>
#include <linux/netfilter.h>
#include <string.h>
#include <stdlib.h>

#include "ctrl.h"
#include "dynsrv.h"
#include "event.h"
#include "ipqmon.h"
#include "logging.h"
#include "readconf.h"
#include "signals.h"

/* Set BUFSIZE to 1500 (ethernet frame size) to prevent
 * errors with ipq_read due to truncated messages.
 * This is only necessary for UDP. A buffer size of
 * 256 seems to be enough to hanlde TCP when there is
 * no data on the SYNs */
#define BUFSIZE 1500


int start_ipq_mon(void) {
	int			status, process;
	u_int8_t		port_mode;
	uint16_t		sport, dport;
	fd_set			rfds;
	struct timeval		mainloop_timeout;
	char			*srcip, *dstip;
	unsigned char		buf[BUFSIZE];
	struct ip_header	*ip;
	struct tcp_header	*tcp;
	struct udp_header	*udp;

	sport		= 0;
	dport		= 0;
	packet		= NULL;
	ip		= NULL;
	tcp		= NULL;
	udp		= NULL;
	port_mode	= PORTCONF_IGNORE;

	logmsg(LOG_DEBUG, 1, "Creating ipq connection monitor.\n");
	if ((h = ipq_create_handle(0, PF_INET)) == NULL) {
		logmsg(LOG_ERR, 1, "Error - Could not create IPQ handle: %s.\n", ipq_errstr());
		clean_exit(EXIT_FAILURE);
	}

	if ((status = ipq_set_mode(h, IPQ_COPY_PACKET, BUFSIZE)) < 0) {
		logmsg(LOG_ERR, 1, "Error - Could not set IPQ mode: %s.\n", ipq_errstr());
		ipq_destroy_handle(h);
		clean_exit(EXIT_FAILURE);
	}

	logmsg(LOG_NOTICE, 1, "---- Trapping attacks via IPQ. ----\n");

	running = 1;

	// receive packets
	mainloop_timeout.tv_sec = 0;
	mainloop_timeout.tv_usec = 0;

	for (;;) {
		FD_ZERO(&rfds);
		FD_SET(sigpipe[0], &rfds);
		FD_SET(h->fd, &rfds);

		switch (select(MAX(h->fd, sigpipe[0]) + 1, &rfds, NULL, NULL, &mainloop_timeout)) {
		case -1:
			if (errno == EINTR) {
				if (check_sigpipe() == -1) exit(EXIT_FAILURE);
				break;
			}
			/* error */
			logmsg(LOG_ERR, 1, "Error - select() call failed in main loop: %m.\n");
			exit(EXIT_FAILURE);
		case 0:
			// select timed out, handle events
			mainloop_timeout.tv_sec = event_execute();
			mainloop_timeout.tv_usec = 0;

			break;
		default:
			if (FD_ISSET(sigpipe[0], &rfds) && (check_sigpipe() == -1))
				exit(EXIT_FAILURE);
			if (FD_ISSET(h->fd, &rfds)) {
				/* incoming connection request */
				process	= 1;
				if ((status = ipq_read(h, buf, BUFSIZE, 0)) < 0) {
					logmsg(LOG_ERR, 1, "Error - Could not read queued packet: %s.\n", ipq_errstr());
					ipq_destroy_handle(h);
					clean_exit(EXIT_FAILURE);
				}
				switch (ipq_message_type(buf)) {
				case NLMSG_ERROR:
					logmsg(LOG_WARN, 1, "IPQ Warning - ipq_read() returned status NLMSG_ERROR: %s\n",
						strerror(ipq_get_msgerr(buf)));
					break;
				case IPQM_PACKET:
					packet	= ipq_get_packet(buf);
					ip	= (struct ip_header*) packet->payload;
					if (ip->ip_p == TCP) {
						tcp		= (struct tcp_header*) (packet->payload + (4 * ip->ip_hlen));
						sport		= ntohs(tcp->th_sport);
						dport		= ntohs(tcp->th_dport);
						port_mode	= port_flags_tcp[dport] ? port_flags_tcp[dport]->mode : 0;
					} else if (ip->ip_p == UDP) {
						udp		= (struct udp_header*) (packet->payload + (4 * ip->ip_hlen));
						sport		= ntohs(udp->uh_sport);
						dport		= ntohs(udp->uh_dport);
						port_mode	= port_flags_udp[dport] ? port_flags_udp[dport]->mode : 0;
					} else {
						logmsg(LOG_ERR, 1, "Error - Protocol %u is not supported.\n", ip->ip_p);
						if ((status = ipq_set_verdict(h, packet->packet_id, NF_ACCEPT, 0, NULL)) < 0) {
							logmsg(LOG_ERR, 1, "Error - Could not set verdict on packet: %s.\n", ipq_errstr());
							ipq_destroy_handle(h);
							clean_exit(EXIT_FAILURE);
						}
						break;
					}

					/* Got a connection request, start dynamic server and pass packet processing back to the kernel */
					if ((srcip = strdup(inet_ntoa(ip->ip_src))) == NULL) {
						logmsg(LOG_ERR, 1, "Error - Unable to allocate memory: %m.\n");
						exit(EXIT_FAILURE);
					}
					if ((dstip = strdup(inet_ntoa(ip->ip_dst))) == NULL) {
						logmsg(LOG_ERR, 1, "Error - Unable to allocate memory: %m.\n");
						exit(EXIT_FAILURE);
					}
					logmsg(LOG_NOISY, 1, "%s:%d requesting %s connection on %s:%d.\n",
						srcip, sport, PROTO(ip->ip_p), dstip, dport);
					free(srcip);
					free(dstip);

					switch (port_mode) {
					case PORTCONF_NONE:
						logmsg(LOG_DEBUG, 1, "Port %u/%s has no explicit configuration.\n",
								dport, PROTO(ip->ip_p));
						if (portconf_default == PORTCONF_IGNORE) {
							logmsg(LOG_DEBUG, 1, "Ignoring connection request per default.\n");
							if ((status = ipq_set_verdict(h, packet->packet_id, NF_ACCEPT, 0, NULL)) < 0) {
								logmsg(LOG_ERR, 1, "Error - Could not set verdict on packet: %s.\n", ipq_errstr());
								ipq_destroy_handle(h);
								clean_exit(EXIT_FAILURE);
							}
							process = 0;
						}
						break;
					case PORTCONF_IGNORE:
						logmsg(LOG_DEBUG, 1, "Port %u/%s is configured to be ignored.\n",
							dport, PROTO(ip->ip_p));
						if ((status = ipq_set_verdict(h, packet->packet_id, NF_ACCEPT, 0, NULL)) < 0) {
							logmsg(LOG_ERR, 1, "Error - Could not set verdict on packet: %s.\n", ipq_errstr());
							ipq_destroy_handle(h);
							clean_exit(EXIT_FAILURE);
						}
						process = 0;
						break;
					case PORTCONF_NORMAL:
						logmsg(LOG_DEBUG, 1, "Port %u/%s is configured to be handled in normal mode.\n",
							dport, PROTO(ip->ip_p));
						break;
					case PORTCONF_MIRROR:
						logmsg(LOG_DEBUG, 1, "Port %u/%s is configured to be handled in mirror mode.\n",
							dport, PROTO(ip->ip_p));
						break;
					case PORTCONF_PROXY:
						logmsg(LOG_DEBUG, 1, "Port %u/%s is configured to be handled in proxy mode\n",
							dport, PROTO(ip->ip_p));
						break;
					default:
						logmsg(LOG_ERR, 1, "Error - Invalid explicit configuration for port %u/%s.\n",
							dport, PROTO(ip->ip_p));
						if ((status = ipq_set_verdict(h, packet->packet_id, NF_ACCEPT, 0, NULL)) < 0) {
							logmsg(LOG_ERR, 1, "Error - Could not set verdict on packet: %s.\n", ipq_errstr());
							ipq_destroy_handle(h);
							clean_exit(EXIT_FAILURE);
						}
						process = 0;
						break;
					}
					
					if (process == 0) break;

					start_dynamic_server(ip->ip_src, htons(sport), ip->ip_dst, htons(dport), ip->ip_p);
					break;
				default:
					logmsg(LOG_DEBUG, 1, "IPQ Warning - Unknown message type.\n");
					break;
				}
			}
		}
	}

	ipq_destroy_handle(h);
	return(1);
}

#endif
