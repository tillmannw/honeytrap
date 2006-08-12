AUTOMAKE_OPTIONS = foreign

LIBS = -ldl
SUBDIRS = doc src

EXTRA_DIST = ChangeLog LICENSE README doc/honeytrap.8 etc/

install-data-local:
	$(mkinstalldirs) $(DESTDIR)/$(sysconfdir)
	$(mkinstalldirs) $(DESTDIR)/$(sysconfdir)/honeytrap
	$(mkinstalldirs) $(DESTDIR)/$(sysconfdir)/honeytrap/responses

	$(INSTALL_DATA) etc/honeytrap.conf.dist $(DESTDIR)/$(sysconfdir)/honeytrap/honeytrap.conf.dist
	$(INSTALL_DATA) etc/honeytrap.conf.dist $(DESTDIR)/$(sysconfdir)/honeytrap/honeytrap.conf
	$(INSTALL_DATA) etc/ports.conf.dist $(DESTDIR)/$(sysconfdir)/honeytrap/portd.conf.dist
	$(INSTALL_DATA) etc/responses/* $(DESTDIR)/$(sysconfdir)/honeytrap/responses
