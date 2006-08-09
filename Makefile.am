AUTOMAKE_OPTIONS = foreign

LIBS = -ldl
SUBDIRS = doc src

EXTRA_DIST = ChangeLog LICENSE README doc/honeytrap.8 etc/

install-data-local:
	$(mkinstalldirs) $(sysconfdir)
	$(mkinstalldirs) $(sysconfdir)/honeytrap
	$(mkinstalldirs) $(sysconfdir)/honeytrap/responses

	$(INSTALL_DATA) etc/honeytrap.conf.dist $(sysconfdir)/honeytrap/honeytrap.conf.dist
	$(INSTALL_DATA) etc/honeytrap.conf.dist $(sysconfdir)/honeytrap/honeytrap.conf
	$(INSTALL_DATA) etc/responses/* $(sysconfdir)/honeytrap/responses
