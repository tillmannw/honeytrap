/* pcapmon.c
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
#ifdef USE_PCAP_MON

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>


#ifndef ETHER_HDRLEN
 #define ETHER_HDRLEN 14
#endif

#include "ctrl.h"
#include "dynsrv.h"
#include "event.h"
#include "logging.h"
#ifndef HAVE_PCAP_BPF_H
  #ifdef HAVE_NET_BPF_H
    #include <net/bpf.h>
  #endif
#endif
#include "pcapmon.h"
#include "readconf.h"
#include "signals.h"
#include "tcpip.h"


u_char *icmp_dissect(const struct ip_header *packet) {
	struct ip_header *ip, *icmp_data;
	u_char *icmp;
	u_int32_t len;

	ip = (struct ip_header *) packet;
	if (ip->ip_p != ICMP) return(NULL);

	/* It's an ICMP message */
	icmp = (u_char *) packet + 4*ip->ip_hl;
	if ((icmp[0] != 3) || (icmp[1] != 3)) return(NULL);

	/* It's 'port unreachable', locate encapsulated IP packet */
	if ((len = ntohs(ip->ip_len) - 4*ip->ip_hl - 8) < 10) {
		logmsg(LOG_ERR, 1, "Error - ICMP message truncated.\n");
		return(NULL);
	}
	icmp_data = (struct ip_header *) ((u_char *) packet + 4*ip->ip_hl + 8);
	if (icmp_data->ip_p != 17) return(NULL);
	
	/* It's a UDP port unreachable response */
	return((u_char *)icmp_data);
}


void server_wrapper(u_char *args, const struct pcap_pkthdr *pheader, const u_char * packet) {
	uint16_t	sport, dport;
	u_int8_t	port_mode;
	char		*srcip, *dstip;

	sport		= 0;
	dport		= 0;
	port_mode	= PORTCONF_IGNORE;

	ip = (struct ip_header *) (packet + pcap_offset);
	if (ip->ip_p == TCP) {
		tcp		= (struct tcp_header *) ((u_char *) ip + (4 * ip->ip_hlen));
		sport		= ntohs(tcp->th_sport);
		dport		= ntohs(tcp->th_dport);
		port_mode	= port_flags_tcp[sport] ? port_flags_tcp[sport]->mode : 0;
	} else if (ip->ip_p == ICMP) {
		if ((ip = (struct ip_header *) icmp_dissect(ip)) == NULL) return;
		udp		= (struct udp_header *) ((u_char *) ip + (4 * ip->ip_hlen));
		sport		= ntohs(udp->uh_sport);
		dport		= ntohs(udp->uh_dport);
		port_mode	= port_flags_udp[dport] ? port_flags_udp[dport]->mode : 0;
	} else {
		logmsg(LOG_ERR, 1, "Error - Protocol %u is not supported.\n", ip->ip_p);
		return;
	}

	if ((srcip = strdup(inet_ntoa(ip->ip_src))) == NULL) {
		logmsg(LOG_ERR, 1, "Error - Unable to allocate memory: %m.\n");
		exit(EXIT_FAILURE);
	}
	if ((dstip = strdup(inet_ntoa(ip->ip_dst))) == NULL) {
		logmsg(LOG_ERR, 1, "Error - Unable to allocate memory: %m.\n");
		exit(EXIT_FAILURE);
	}
	if (ip->ip_p == UDP)
		logmsg(LOG_NOISY, 1, "%s:%d requesting udp connection on %s:%d.\n",
		srcip, sport, dstip, dport);
	else if (ip->ip_p == TCP)
		logmsg(LOG_NOISY, 1, "%s:%d requesting tcp connection on %s:%d.\n",
		dstip, dport, srcip, sport);
	free(srcip);
	free(dstip);

	switch (port_mode) {
	case PORTCONF_NONE:
		logmsg(LOG_DEBUG, 1, "Port %u/%s has no explicit configuration.\n", sport, PROTO(ip->ip_p));
		if (portconf_default == PORTCONF_IGNORE) {
			logmsg(LOG_DEBUG, 1, "Ignoring connection request per default.\n");
			return;
		}
		break;
	case PORTCONF_IGNORE:
		logmsg(LOG_DEBUG, 1, "Port %u/%s is configured to be ignored.\n", sport, PROTO(ip->ip_p));
		return;
	case PORTCONF_NORMAL:
		logmsg(LOG_DEBUG, 1, "Port %u/%s is configured to be handled in normal mode.\n",
			sport, PROTO(ip->ip_p));
		break;
	case PORTCONF_MIRROR:
		logmsg(LOG_DEBUG, 1, "Port %u/%s is configured to be handled in mirror mode.\n",
			sport, PROTO(ip->ip_p));
		break;
	case PORTCONF_PROXY:
		logmsg(LOG_DEBUG, 1, "Port %u/%s is configured to be handled in proxy mode\n", sport, PROTO(ip->ip_p));
		break;
	default:
		logmsg(LOG_ERR, 1, "Error - Invalid explicit configuration for port %u/%s.\n", sport, PROTO(ip->ip_p));
		return;
	}

	if (ip->ip_p == UDP) start_dynamic_server(ip->ip_src, htons(sport), ip->ip_dst, htons(dport), ip->ip_p);
	else if (ip->ip_p == TCP) start_dynamic_server(ip->ip_dst, htons(dport), ip->ip_src, htons(sport), ip->ip_p);

	return;
}


int start_pcap_mon(void) {
	char			errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program	filter;
	bpf_u_int32		mask;
	bpf_u_int32		net;
	int			pcap_fd;
	struct timeval		mainloop_timeout;
	fd_set			rfds;

	logmsg(LOG_DEBUG, 1, "Creating pcap connection monitor.\n");

	if (!dev) {
		logmsg(LOG_WARN, 1, "Warning - No device given, trying to use default device.\n");
		if ((dev = pcap_lookupdev(errbuf)) == NULL) {
			logmsg(LOG_ERR, 1, "Error - Could not find default device: %s\n", errbuf);
			exit(EXIT_FAILURE);
		}
	}

	logmsg(LOG_DEBUG, 1, "Looking up device properties for %s.\n", dev);
	/* Find the properties for the device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		logmsg(LOG_WARN, 1, "Could not get netmask: %s\n", errbuf);
		net = 0;
		mask = 0;
	}

	/* create pcap sniffer */
	logmsg(LOG_DEBUG, 1, "Creating pcap sniffer on %s.\n", dev);
	if ((packet_sniffer = pcap_open_live(dev, BUFSIZ, promisc_mode, 10, errbuf)) == NULL) {
		logmsg(LOG_ERR, 1, "Error - Could not open %s for sniffing: %s.\n", dev, errbuf);
		logmsg(LOG_ERR, 1, "Do you have root privileges?\n");
		clean_exit(EXIT_FAILURE);
	}

	switch (pcap_datalink(packet_sniffer)) {
#ifdef DLT_RAW
		case DLT_RAW:
			pcap_offset = 0;
			break;
#endif
#ifdef DLT_SLIP
		case DLT_SLIP:
#endif
#ifdef DLT_PPP
		case DLT_PPP:
#endif
#ifdef DLT_PPP_SERIAL
		case DLT_PPP_SERIAL:
			pcap_offset = 2;
			break;
#endif
#ifdef DLT_NULL
		case DLT_NULL:
#endif
#ifdef DLT_LOOP
		case DLT_LOOP:
			pcap_offset = 4;
			break;
#endif
#ifdef DLT_SUNATM
		case DLT_SUNATM:
			pcap_offset = 8;
			break;
#endif
#ifdef DLT_EN10MB
		case DLT_EN10MB:
			pcap_offset = ETHER_HDRLEN;
			break;
#endif
#ifdef DLT_LINUX_SLL
		case DLT_LINUX_SLL:
			pcap_offset = 16;
			break;
#endif
#ifdef DLT_FDDI
		case DLT_FDDI:
			pcap_offset = 21;
			break;
#endif
#ifdef DLT_IEEE802
		case DLT_IEEE802:
			pcap_offset = 22;
			break;
#endif
#ifdef DLT_PFLOG
		case DLT_PFLOG:
			pcap_offset = 50;
			break;
#endif
		default:
			logmsg(LOG_ERR, 1, "Error - Link type of %s is currently not supported.\n", dev);
			clean_exit(EXIT_FAILURE);
			break;
	}
	logmsg(LOG_DEBUG, 1, "Using a %d bytes offset for %s.\n",
		pcap_offset, pcap_datalink_val_to_name(pcap_datalink(packet_sniffer)));

	/* compile bpf for tcp RST fragments */
	if (pcap_compile(packet_sniffer, &filter, bpf_filter_string, 1, net) == -1) {
		logmsg(LOG_ERR, 1, "Pcap error - Invalid BPF string: %s.\n", errbuf);
		clean_exit(EXIT_FAILURE);
	}
	if (pcap_setfilter(packet_sniffer, &filter) == -1) {
		logmsg(LOG_ERR, 1, "Pcap error - Unable to start tcp sniffer: %s\n", errbuf);
		clean_exit(EXIT_FAILURE);
	}
	pcap_freecode(&filter);

	/* enable non-blocking mode to be able to select() */
	if (pcap_setnonblock(packet_sniffer, 1, errbuf) == -1) {
		logmsg(LOG_ERR, 1, "Pcap error - Unable to set capture descriptor to non-blocking: %s\n", errbuf);
		clean_exit(EXIT_FAILURE);
	}

	/* get a selectable file descriptor */
	if ((pcap_fd = pcap_get_selectable_fd(packet_sniffer)) == -1) {
		logmsg(LOG_ERR, 1, "Pcap error - Capture descriptor does not support select().\n");
		clean_exit(EXIT_FAILURE);
	}

	logmsg(LOG_NOTICE, 1, "---- Trapping attacks on device '%s' via PCAP. ----\n", dev);

	running = 1;

	// receive packets
	mainloop_timeout.tv_sec = 0;
	mainloop_timeout.tv_usec = 0;

	for (;;) {
		FD_ZERO(&rfds);
		FD_SET(sigpipe[0], &rfds);
		FD_SET(pcap_fd, &rfds);

		switch (select(MAX(pcap_fd, sigpipe[0]) + 1, &rfds, NULL, NULL, &mainloop_timeout)) {
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

			/*
			 * We have to call the dispatcher here because pcap_get_selectable_fd() on OpenBSD requires special treatment:
			 * pcap_get_selectable_fd() returns a valid fd, but select() does not necessarily return in case of events on it.
			 * Calling the dispatcher on timeouts works around this
			 */
                        if (pcap_dispatch(packet_sniffer, -1, (void *) server_wrapper, NULL) < 0) {
                                logmsg(LOG_ERR, 1, "Pcap error - Unable to process packet: %s.\n", pcap_geterr(packet_sniffer));
                                exit(EXIT_FAILURE);
                        }

			break;
		default:
			if (FD_ISSET(sigpipe[0], &rfds) && (check_sigpipe() == -1))
				exit(EXIT_FAILURE);
			if (FD_ISSET(pcap_fd, &rfds)) {
				/* incoming connection request */
				if (pcap_dispatch(packet_sniffer, -1, (void *) server_wrapper, NULL) < 0) {
					logmsg(LOG_ERR, 1, "Pcap error - Unable to process packet: %s.\n", pcap_geterr(packet_sniffer));
					exit(EXIT_FAILURE);
				}
			}
			break;
		}
	}

	pcap_close(packet_sniffer); // never reached
	return(1);
}


char *create_bpf(char *bpf_cmd_ext, struct hostent *ip_cmd_opt, const char *dev) {
	char *bpf_filter_string = NULL, *bpf_ip_filter = NULL, errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *alldevsp = NULL;
	pcap_if_t *curdev = NULL;
	pcap_addr_t *curaddr = NULL;
	uint32_t oldstrsize = 0, newstrsize = 0;
	int dev_found;

	if (pcap_findalldevs(&alldevsp, errbuf) == -1) {
		logmsg(LOG_ERR, 1, "Error - Unable to find network devices for pcap: %s\n",errbuf);
		exit(EXIT_FAILURE);
	}

	/* determine ip address of device */
	if (dev == NULL) {
		if ((dev = strdup("any")) == NULL) {
			fprintf(stderr, "Error - Unable to allocate memory: %m.\n");
			exit(EXIT_FAILURE);
		}
	}

	/* assemble filter string */
	bpf_filter_string = strdup("((tcp[13] & 0x04 != 0 and tcp[4:4] == 0) or (icmp[0] == 3 and icmp[1] == 3))");

	/* add ip addresses for chosen devices */
	dev_found = 0;
	for(curdev = alldevsp; curdev && (dev_found == 0); curdev = curdev->next) {
		DEBUG_FPRINTF(stdout, "  Processing interface %s.\n",curdev->name);
		/* advance through device list until name matches command line argument, process all for 'any' */

		if ((strcmp(dev, "any") != 0) && (strcmp(curdev->name, dev) != 0)) continue;
		else if (strcmp(dev, "any") != 0) dev_found = 1;

		for (curaddr = curdev->addresses; curaddr != NULL; curaddr = curaddr->next) {
			if (curaddr->addr == NULL) continue;
			if (!curaddr->addr->sa_family) continue;
			switch(curaddr->addr->sa_family) {
			case AF_INET:
				DEBUG_FPRINTF(stdout, "    Interface %s has an AF_INET address.\n", curdev->name);
				oldstrsize = (bpf_ip_filter ? strlen(bpf_ip_filter) : 0);
				newstrsize = strlen(inet_ntoa(*(struct in_addr*)
					&(((struct sockaddr_in *)curaddr->addr)->sin_addr)));
				if (!bpf_ip_filter) {
					if ((bpf_ip_filter = (char *) malloc(newstrsize+1)) == NULL) {
						fprintf(stderr, "Error - Unable to allocate memory: %m.\n");
						exit(EXIT_FAILURE);
					}
					snprintf(bpf_ip_filter, newstrsize+1, "%s%c",
						inet_ntoa(*(struct in_addr*)
						&(((struct sockaddr_in *)curaddr->addr)->sin_addr)), 0);
				} else {
					if ((bpf_ip_filter = (char *) realloc(bpf_ip_filter, oldstrsize+21)) == NULL) {
						fprintf(stderr, "Error - Unable to allocate memory: %m.\n");
						exit(EXIT_FAILURE);
					}
					snprintf(bpf_ip_filter+oldstrsize, 21, " or %s%c",
						inet_ntoa(*(struct in_addr*)
						&(((struct sockaddr_in *)curaddr->addr)->sin_addr)), 0);
				}
				break;
			default:
				DEBUG_FPRINTF(stdout, "    Interface %s has unknown address family %u.\n",
					curdev->name, curaddr->addr->sa_family);

			}
		}
	}
	pcap_freealldevs(alldevsp);
	if ((strcmp(dev, "any") != 0) && (!dev_found)) {
		fprintf(stderr, "  Error - No such interface: %s.\n", dev);
		exit(EXIT_FAILURE);
	}
	
	if (ip_cmd_opt) {
		/* add ip address from -a command line option to filter string */
		if ((bpf_filter_string = (char *) realloc(bpf_filter_string, strlen(bpf_filter_string)+37)) == NULL) {
			fprintf(stderr, "Error - Unable to allocate memory: %m.\n");
			exit(EXIT_FAILURE);
		}
		snprintf(bpf_filter_string+strlen(bpf_filter_string), 
			strlen((char *) inet_ntoa(*(struct in_addr*)ip_cmd_opt->h_addr_list[0]))+17,
			" and (src host %s)%c", (char*) inet_ntoa(*(struct in_addr*)ip_cmd_opt->h_addr_list[0]), 0);
	} else if (bpf_ip_filter) {
		/* add addresses guessed from interfaces to bpf string */
		if ((bpf_filter_string = (char *) realloc(bpf_filter_string, strlen(bpf_filter_string)+strlen(bpf_ip_filter)+19)) == NULL) {
			fprintf(stderr, "Error - Unable to allocate memory: %m.\n");
			exit(EXIT_FAILURE);
		}
		snprintf(bpf_filter_string + strlen(bpf_filter_string), strlen(bpf_ip_filter)+19, 
			" and (src host (%s))%c", bpf_ip_filter, 0);
	}

	/* add bpf expression from command line */
	if (bpf_cmd_ext) {
		if ((bpf_filter_string = (char *)realloc(bpf_filter_string,
			strlen(bpf_filter_string)+strlen(bpf_cmd_ext)+8)) == NULL) {
			fprintf(stderr, "  Error - Unable to allocate memory: %m.\n");
			exit(EXIT_FAILURE);
		}	
		snprintf(bpf_filter_string+strlen(bpf_filter_string), strlen(bpf_cmd_ext)+8,
			" and (%s)%c", bpf_cmd_ext, 0);
	}
	DEBUG_FPRINTF(stdout, "  BPF string is '%s'.\n", bpf_filter_string);

	return(bpf_filter_string);
}

#endif
