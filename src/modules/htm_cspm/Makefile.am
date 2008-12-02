AUTOMAKE_OPTIONS = foreign no-dependencies

AM_CFLAGS=-Wall -Werror -Wno-unused

#AM_LDFLAGS = -lpcre -ly -lfl
AM_LDFLAGS = -lpcre

AM_YFLAGS = -d

INCLUDES = -I../../

BUILT_SOURCES = signature_parser.h

libdir=$(DESTDIR)/$(sysconfdir)/honeytrap/plugins

lib_LTLIBRARIES = htm_cspm.la

htm_cspm_la_SOURCES = htm_cspm.c htm_cspm.h
htm_cspm_la_SOURCES += signature_parser.y signature_scanner.l
htm_cspm_la_SOURCES += signature_parser.h
htm_cspm_la_SOURCES += sc_shellcode.c sc_shellcode.h
htm_cspm_la_SOURCES += sf_preproc_info.h
htm_cspm_la_SOURCES += sc_action.c sc_action.h
htm_cspm_la_SOURCES += sc_buffer.c sc_buffer.h
htm_cspm_la_SOURCES += connectback.c connectback.h
htm_cspm_la_LDFLAGS = -module -no-undefined -avoid-version


install-exec-am:
	$(mkinstalldirs) $(libdir)
	for module in `find .libs -name htm_*.so`; do \
		[ -h $$module ] || $(INSTALL_DATA) "$$module" $(libdir) ; \
	done
