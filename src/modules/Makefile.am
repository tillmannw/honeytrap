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
	htm_deUnicode.la \
	htm_b64Decode.la

if BUILD_SPAMSUM_PLUGIN
lib_LTLIBRARIES += htm_SpamSum.la
endif

if BUILD_CPUEMU_PLUGIN
lib_LTLIBRARIES += htm_cpuEmu.la
endif

if BUILD_CLAMAV_PLUGIN
lib_LTLIBRARIES += htm_ClamAV.la
endif

if BUILD_SUBMIT_MWSERV_PLUGIN
lib_LTLIBRARIES += htm_submitMWserv.la
endif

if BUILD_SUBMIT_NEBULA_PLUGIN
lib_LTLIBRARIES += htm_submitNebula.la
endif

if BUILD_SUBMIT_POSTGRES_PLUGIN
lib_LTLIBRARIES += htm_submitPostgres.la
endif

if BUILD_XMATCH_PLUGIN
lib_LTLIBRARIES += htm_xmatch.la
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

htm_deUnicode_la_SOURCES = htm_deUnicode.c htm_deUnicode.h
htm_deUnicode_la_LDFLAGS = -module -no-undefined -avoid-version

htm_b64Decode_la_SOURCES = htm_b64Decode.c htm_b64Decode.h
htm_b64Decode_la_LDFLAGS = -module -no-undefined -avoid-version

if BUILD_MAGICPE_PLUGIN
lib_LTLIBRARIES += htm_magicPE.la
htm_magicPE_la_LDFLAGS = -module -no-undefined -avoid-version -lmagic
endif

if BUILD_SPAMSUM_PLUGIN
htm_SpamSum_la_SOURCES = htm_SpamSum.c htm_SpamSum.h
htm_SpamSum_la_LDFLAGS = -module -no-undefined -avoid-version
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
htm_submitMWserv_la = htm_submitMWserv.c htm_submitMWserv.h
htm_submitMWserv_la_LDFLAGS = -module -no-undefined -avoid-version -lcurl
endif

if BUILD_SUBMIT_NEBULA_PLUGIN
htm_submitNebula_la = htm_submitNebula.c htm_submitNebula.h
htm_submitNebula_la_LDFLAGS = -module -no-undefined -avoid-version -lnebula
endif

if BUILD_SUBMIT_POSTGRES_PLUGIN
htm_submitPostgres_la = htm_submitPostgres.c htm_submitPostgres.h
htm_submitPostgres_la_LDFLAGS = -module -no-undefined -avoid-version -lpq
endif

if BUILD_XMATCH_PLUGIN
htm_xmatch_la = htm_xmatch.c
htm_xmatch_la_LDFLAGS = -module -no-undefined -avoid-version -lxmatch
endif

if BUILD_LOGATTACKER_PLUGIN
lib_LTLIBRARIES += htm_logAttacker.la
htm_logAttacker_la = htm_logAttacker.c
htm_logAttacker_la_LDFLAGS = -module -no-undefined -avoid-version
endif

if BUILD_LOGJSON_PLUGIN
lib_LTLIBRARIES += htm_logJSON.la
htm_logJSON_la = htm_logJSON.c
htm_logJSON_la_LDFLAGS = -module -no-undefined -avoid-version -ljson-c
endif


if BUILD_CSPM_PLUGIN
SUBDIRS += htm_cspm
endif


install-exec-am:
	$(mkinstalldirs) $(libdir)
	for module in `find .libs -name htm_*.so`; do \
		[ -h $$module ] || $(INSTALL_DATA) "$$module" $(libdir) ; \
	done
