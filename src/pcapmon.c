/* pcapmon.c
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
#ifdef USE_PCAP_MON

#include <errno.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "pcapmon.h"

#ifndef HAVE_PCAP_BPF_H
  #ifdef HAVE_NET_BPF_H
    #include <net/bpf.h>
  #endif
#endif

#ifndef ETHER_HDRLEN
 #define ETHER_HDRLEN 14
#endif

#include "pcapmon.h"
#include "logging.h"
#include "dynsrv.h"
#include "ctrl.h"


void tcp_server_wrapper(u_char *args, const struct pcap_pkthdr *pheader, const u_char * packet) {
	ip = (struct ip_header *) (packet + pcap_offset);
	tcp = (struct tcp_header *) (packet + pcap_offset + ip->ip_hl * 4);

	switch (port_flags[ntohs(tcp->th_sport)]) {
	case PORTCONF_NONE:
		logmsg(LOG_DEBUG, 1, "Port %u/tcp has no explicit configuration.\n", ntohs(tcp->th_sport));
		break;
	case PORTCONF_IGNORE:
		logmsg(LOG_DEBUG, 1, "Port %u/tcp is configured to be ignored.\n", ntohs(tcp->th_sport));
		return;
	case PORTCONF_NORMAL:
		logmsg(LOG_DEBUG, 1, "Port %u/tcp is configured to be handled in normal mode.\n", ntohs(tcp->th_sport));
		break;
	case PORTCONF_MIRROR:
		logmsg(LOG_DEBUG, 1, "Port %u/tcp is configured to be handled in mirror mode.\n", ntohs(tcp->th_sport));
		break;
	case PORTCONF_PROXY:
		logmsg(LOG_DEBUG, 1, "Port %u/tcp is configured to be handled in proxy mode\n", ntohs(tcp->th_sport));
		break;
	default:
		logmsg(LOG_ERR, 1, "Error - Invalid explicit configuration for port %u/tcp.\n", ntohs(tcp->th_sport));
		return;
	}

	logmsg(LOG_INFO, 1, "Connection request on port %d.\n", ntohs(tcp->th_sport));
	start_dynamic_server(ip->ip_dst, tcp->th_dport, ip->ip_src, tcp->th_sport, ip->ip_p);
	return;
}


int start_pcap_mon(void) {
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program filter;
	bpf_u_int32 mask;
	bpf_u_int32 net;

	logmsg(LOG_DEBUG, 1, "Creating pcap connection monitor.\n");

	if (!dev) {
		logmsg(LOG_WARN, 1, "Warning - No device given, trying to use default device.\n");
		if ((dev = pcap_lookupdev(errbuf)) == NULL) {
			logmsg(LOG_ERR, 1, "Error - Could not find default device: %s\n", errbuf);
			exit(1);
		}
	}

	logmsg(LOG_DEBUG, 1, "Looking up device properties for %s.\n", dev);
	/* Find the properties for the device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		logmsg(LOG_WARN, 1, "Could not get netmask: %s\n", errbuf);
		net = 0;
		mask = 0;
	}

	/* sniff RST packets */
	logmsg(LOG_DEBUG, 1, "Starting pcap sniffer on %s.\n", dev);
	if ((tcp_sniffer = pcap_open_live(dev, BUFSIZ, promisc_mode, 10, errbuf)) != NULL) {
		switch (pcap_datalink(tcp_sniffer)) {
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
				exit(1);
				break;
		}
		logmsg(LOG_DEBUG, 1, "Using a %d bytes offset for %s.\n",
			pcap_offset, pcap_datalink_val_to_name(pcap_datalink(tcp_sniffer)));

		/* compile bpf for tcp RST fragments */
		if (pcap_compile(tcp_sniffer, &filter, bpf_filter_string, 1, net) == -1) {
                	logmsg(LOG_ERR, 1, "Pcap error - Invalid BPF string: %s.\n", errbuf);
                	clean_exit(0);
        	}
		if (pcap_setfilter(tcp_sniffer, &filter) == -1) {
			logmsg(LOG_ERR, 1, "Pcap error - Unable to start tcp sniffer: %s\n", errbuf);
			clean_exit(0);
		}
		pcap_freecode(&filter);

		logmsg(LOG_NOTICE, 1, "---- Trapping attacks on %s. ----\n", dev);

		pcap_loop(tcp_sniffer, -1, (void *) tcp_server_wrapper, NULL);

		pcap_close(tcp_sniffer);
	} else {
		logmsg(LOG_ERR, 1, "Error - Could not open %s for sniffing: %s.\n", dev, errbuf);
		logmsg(LOG_ERR, 1, "Do you have root privileges?\n");
		clean_exit(0);
	}
	return(1);
}


char *create_bpf(char *bpf_cmd_ext, struct hostent *ip_cmd_opt, const char *dev) {
	char *bpf_filter_string = NULL, *bpf_ip_filter = NULL, errbuf[PCAP_ERRBUF_SIZE];
	struct in_addr netaddr, netmask;
	pcap_if_t *alldevsp = NULL;
	pcap_if_t *curdev = NULL;
	pcap_addr_t *curaddr = NULL;
	struct sockaddr *saptr = NULL;
	uint32_t oldstrsize = 0, newstrsize = 0;
	int dev_found;

	if (pcap_findalldevs(&alldevsp, errbuf) == -1) {
		logmsg(LOG_ERR, 1, "Error - Unable to find network devices for pcap: %s\n",errbuf);
		exit(1);
	}

	/* determine ip address of device */
	if (dev == NULL) {
		dev = (char *) malloc(4);
		dev = "any";
	} else if ((strcmp(dev, "any") != 0)) {
		/* lookup net address and netmask for interface */
		pcap_lookupnet((char *) dev, &net, &mask, errbuf);
		netaddr.s_addr = net;
		netmask.s_addr = mask;
	}

	/* assemble filter string */
	bpf_filter_string = strdup("(tcp[13] & 0x04 != 0) and (tcp[4:2] == 0)");

	/* add ip addresses for chosen devices */
	dev_found = 0;
	for(curdev = alldevsp; curdev && (dev_found == 0); curdev = curdev->next) {
		DEBUG_FPRINTF(stdout, "  Processing interface %s.\n",curdev->name);
		/* advance through device list until name matches command line argument, process all for 'any' */

		if ((strcmp(dev, "any") != 0) && (strcmp(curdev->name, dev) != 0)) continue;
		else if (strcmp(dev, "any") != 0) dev_found = 1;

		for (curaddr = curdev->addresses; curaddr != NULL; curaddr = curaddr->next) {
			if (curaddr->addr == NULL) continue;
			saptr = curaddr->addr;
			if (!curaddr->addr->sa_family) continue;
			switch(curaddr->addr->sa_family) {
			case AF_INET:
				DEBUG_FPRINTF(stdout, "    Interface %s has an AF_INET address.\n", curdev->name);
				oldstrsize = (bpf_ip_filter ? strlen(bpf_ip_filter) : 0);
				newstrsize = strlen(inet_ntoa(*(struct in_addr*)
					&(((struct sockaddr_in *)curaddr->addr)->sin_addr)));
				if (!bpf_ip_filter) {
					bpf_ip_filter = (char *) malloc(newstrsize+1);
					snprintf(bpf_ip_filter, newstrsize+1, "%s%c",
						inet_ntoa(*(struct in_addr*)
						&(((struct sockaddr_in *)curaddr->addr)->sin_addr)), 0);
				} else {
					bpf_ip_filter = (char *) realloc(bpf_ip_filter, oldstrsize+21);
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
		exit(1);
	}
	
	if (ip_cmd_opt) {
		/* add ip address from -a command line option to filter string */
		bpf_filter_string = (char *) realloc(bpf_filter_string, strlen(bpf_filter_string)+37);
		snprintf(bpf_filter_string+strlen(bpf_filter_string), 
			strlen((char *) inet_ntoa(*(struct in_addr*)ip_cmd_opt->h_addr_list[0]))+17,
			" and (src host %s)%c", (char*) inet_ntoa(*(struct in_addr*)ip_cmd_opt->h_addr_list[0]), 0);
	} else if (bpf_ip_filter) {
		/* add addresses guessed from interfaces to bpf string */
		bpf_filter_string = (char *) realloc(bpf_filter_string, strlen(bpf_filter_string)+strlen(bpf_ip_filter)+19);
		snprintf(bpf_filter_string + strlen(bpf_filter_string), strlen(bpf_ip_filter)+19, 
			" and (src host (%s))%c", bpf_ip_filter, 0);
	}

	/* add bpf expression from command line */
	if (bpf_cmd_ext) {
		if (!(bpf_filter_string = (char *)realloc(bpf_filter_string,
			strlen(bpf_filter_string)+strlen(bpf_cmd_ext)+8))) {
			fprintf(stderr, "  Error - Unable to allocate memory: %s\n", strerror(errno));
			exit(1);
		}	
		snprintf(bpf_filter_string+strlen(bpf_filter_string), strlen(bpf_cmd_ext)+8,
			" and (%s)%c", bpf_cmd_ext, 0);
	}
	fprintf(stdout, "  BPF string is '%s'.\n", bpf_filter_string);

	return(bpf_filter_string);
}

#endif
