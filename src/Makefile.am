AUTOMAKE_OPTIONS=foreign no-dependencies

AM_CFLAGS=-export-dynamic -Wall -Werror 

sbin_PROGRAMS = honeytrap
honeytrap_SOURCES = 	honeytrap.c honeytrap.h \
			logging.c logging.h \
			event.c event.h \
			ctrl.c ctrl.h \
			queue.c queue.h \
			signals.c signals.h \
			readconf.c readconf.h \
			parseconf.c parseconf.h \
			conftree.c conftree.h \
			plugin.c plugin.h \
			plughook.c plughook.h \
			util.c util.h \
			connectmon.c connectmon.h \
			response.c response.h \
			dynsrv.c dynsrv.h \
			attack.c attack.h \
			tcpip.h \
			sock.c sock.h \
			proxy.c proxy.h \
			sha512.c sha512.h \
			md5.c md5.h

if PCAP_MON
honeytrap_SOURCES +=	pcapmon.c pcapmon.h
endif

if IPQ_MON
honeytrap_SOURCES += 	ipqmon.c ipqmon.h
endif

if NFQ_MON
honeytrap_SOURCES += 	nfqmon.c nfqmon.h
endif

SUBDIRS = modules
