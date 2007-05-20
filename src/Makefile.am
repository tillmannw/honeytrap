AUTOMAKE_OPTIONS=foreign no-dependencies

AM_CFLAGS=-export-dynamic -Wall -Werror 

sbin_PROGRAMS = honeytrap
honeytrap_SOURCES = 	honeytrap.c honeytrap.h \
			logging.c logging.h \
			ctrl.c ctrl.h \
			signals.c signals.h \
			readconf.c readconf.h \
			parseconf.c parseconf.h \
			conftree.c conftree.h \
			plugin.c plugin.h \
			plughook.c plughook.h \
			util.c util.h \
			connectmon.c connectmon.h \
 			pcapmon.c pcapmon.h \
			ipqmon.c ipqmon.h \
			nfqmon.c nfqmon.h \
			response.c response.h \
			dynsrv.c dynsrv.h \
			attack.c attack.h \
			ip.h \
			tcp.c tcp.h \
			udp.c udp.h \
			proxy.c proxy.h \
			sha512.c sha512.h \
			md5.c md5.h

SUBDIRS = modules
