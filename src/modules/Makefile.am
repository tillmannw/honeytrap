AUTOMAKE_OPTIONS = foreign no-dependencies

AM_YFLAGS = -d

INCLUDES = -I../

libdir=$(DESTDIR)/$(sysconfdir)/honeytrap/plugins

lib_LTLIBRARIES = htm_aSaveFile.la htm_ftpDownload.la htm_tftpDownload.la htm_vncDownload.la htm_b64Decode.la htm_SpamSum.la

htm_aSaveFile_la_SOURCES = htm_aSaveFile.c htm_aSaveFile.h
htm_aSaveFile_la_LDFLAGS = -module -no-undefined -avoid-version

htm_ftpDownload_la_SOURCES = htm_ftpDownload.c htm_ftpDownload.h
htm_ftpDownload_la_LDFLAGS = -module -no-undefined -avoid-version

htm_tftpDownload_la_SOURCES = htm_tftpDownload.c htm_tftpDownload.h
htm_tftpDownload_la_LDFLAGS = -module -no-undefined -avoid-version

htm_vncDownload_la_SOURCES = htm_vncDownload.c htm_vncDownload.h
htm_vncDownload_la_LDFLAGS = -module -no-undefined -avoid-version

htm_b64Decode_la_SOURCES = htm_b64Decode.c htm_b64Decode.h
htm_b64Decode_la_LDFLAGS = -module -no-undefined -avoid-version

htm_SpamSum_la_SOURCES = htm_SpamSum.c htm_SpamSum.h
htm_SpamSum_la_LDFLAGS = -module -no-undefined -avoid-version

install-exec-am:
	$(mkinstalldirs) $(DESTDIR)/$(sysconfdir)/honeytrap/plugins
	for module in `find .libs -name htm_*.so | grep -v SpamSum`; do \
		[ -h $$module ] || $(INSTALL_DATA) "$$module" $(DESTDIR)/$(sysconfdir)/honeytrap/plugins/ ; \
	done
	for module in `find . -name htm_*.*a | grep -v SpamSum`; do \
		rm -f $(DESTDIR)/$(sysconfdir)/honeytrap/plugins/`basename "$$module"` ; \
	done
