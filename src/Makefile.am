AUTOMAKE_OPTIONS=foreign no-dependencies

AM_CFLAGS=-export-dynamic

sbin_PROGRAMS = honeytrap
honeytrap_SOURCES = 	honeytrap.c honeytrap.h \
			logging.c logging.h \
			ctrl.c ctrl.h \
			signals.c signals.h \
			readconf.c readconf.h \
			plugin.c plugin.h \
			plughook.c plughook.h \
			util.c util.h \
			connectmon.c connectmon.h \
 			pcapmon.c pcapmon.h \
			ipqmon.c ipqmon.h \
			response.c response.h \
			tcpserver.c tcpserver.h \
			proxy.c proxy.h \
			md5.c md5.h

SUBDIRS = modules
