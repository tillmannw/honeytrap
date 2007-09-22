AUTOMAKE_OPTIONS = foreign no-dependencies

AM_CFLAGS=-Wall -Werror

INCLUDES = -I../

SUBDIRS=

libdir=$(DESTDIR)/$(sysconfdir)/honeytrap/plugins

lib_LTLIBRARIES = \
	htm_SaveFile.la \
	htm_ftpDownload.la \
	htm_httpDownload.la \
	htm_tftpDownload.la \
	htm_vncDownload.la \
	htm_b64Decode.la

if BUILD_SPAMSUM_PLUGIN
lib_LTLIBRARIES += htm_SpamSum.la
endif

if BUILD_POSTGRES_PLUGIN
lib_LTLIBRARIES += htm_SavePostgres.la
endif

if BUILD_CPUEMU_PLUGIN
lib_LTLIBRARIES += htm_cpuEmu.la
endif

if BUILD_CLAMAV_PLUGIN
lib_LTLIBRARIES += htm_ClamAV.la
endif

if BUILD_SUBMIT_MWSERV_PLUGIN
lib_LTLIBRARIES += htm_submitMwserv.la
endif

htm_SaveFile_la_SOURCES = htm_SaveFile.c htm_SaveFile.h
htm_SaveFile_la_LDFLAGS = -module -no-undefined -avoid-version

htm_ftpDownload_la_SOURCES = htm_ftpDownload.c htm_ftpDownload.h
htm_ftpDownload_la_LDFLAGS = -module -no-undefined -avoid-version

htm_httpDownload_la_SOURCES = htm_httpDownload.c htm_httpDownload.h
htm_httpDownload_la_LDFLAGS = -module -no-undefined -avoid-version

htm_tftpDownload_la_SOURCES = htm_tftpDownload.c htm_tftpDownload.h
htm_tftpDownload_la_LDFLAGS = -module -no-undefined -avoid-version

htm_vncDownload_la_SOURCES = htm_vncDownload.c htm_vncDownload.h
htm_vncDownload_la_LDFLAGS = -module -no-undefined -avoid-version

htm_b64Decode_la_SOURCES = htm_b64Decode.c htm_b64Decode.h
htm_b64Decode_la_LDFLAGS = -module -no-undefined -avoid-version

if BUILD_SPAMSUM_PLUGIN
htm_SpamSum_la_SOURCES = htm_SpamSum.c htm_SpamSum.h
htm_SpamSum_la_LDFLAGS = -module -no-undefined -avoid-version
endif

if BUILD_POSTGRES_PLUGIN
htm_SavePostgres_la_SOURCES = htm_SavePostgres.c htm_SavePostgres.h
htm_SavePostgres_la_LDFLAGS = -module -no-undefined -avoid-version -lpq
endif

if BUILD_CPUEMU_PLUGIN
htm_cpuEmu_la_SOURCES = htm_cpuEmu.c htm_cpuEmu.h
htm_cpuEmu_la_LDFLAGS = -module -no-undefined -avoid-version -lemu
endif

if BUILD_CLAMAV_PLUGIN
htm_ClamAV_la = htm_ClamAV.c htm_ClamAV.h
htm_ClamAV_la_LDFLAGS = -module -no-undefined -avoid-version
endif

if BUILD_SUBMIT_MWSERV_PLUGIN
htm_submitMwserv_la = htm_submitMwserv.c htm_submitMwserv.h
htm_submitMwserv_la_LDFLAGS = -module -no-undefined -avoid-version
endif


if BUILD_CSPM_PLUGIN
SUBDIRS += htm_cspm
endif

install-exec-am:
	$(mkinstalldirs) $(DESTDIR)/$(sysconfdir)/honeytrap/plugins
	for module in `find .libs -name htm_*.so`; do \
		[ -h $$module ] || $(INSTALL_DATA) "$$module" $(DESTDIR)/$(sysconfdir)/honeytrap/plugins/ ; \
	done
	for module in `find . -name htm_*.*a`; do \
		rm -f $(DESTDIR)/$(sysconfdir)/honeytrap/plugins/`basename "$$module"` ; \
	done
