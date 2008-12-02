AUTOMAKE_OPTIONS = foreign

LIBS = -ldl
SUBDIRS = doc src

EXTRA_DIST = ChangeLog LICENSE README doc/honeytrap.8 etc/

libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck

install-data-local:
	$(mkinstalldirs) $(DESTDIR)/$(sysconfdir)
	$(mkinstalldirs) $(DESTDIR)/$(sysconfdir)/honeytrap
	$(mkinstalldirs) $(DESTDIR)/$(sysconfdir)/honeytrap/responses
	$(mkinstalldirs) $(DESTDIR)/$(localstatedir)/honeytrap

	install -d $(DESTDIR)/$(localstatedir)/honeytrap/attacks -g nogroup -m 775
	install -d $(DESTDIR)/$(localstatedir)/honeytrap/downloads -g nogroup -m 775

	$(INSTALL_DATA) etc/honeytrap.conf.dist $(DESTDIR)/$(sysconfdir)/honeytrap/honeytrap.conf.dist
	test -f $(DESTDIR)/$(sysconfdir)/honeytrap/honeytrap.conf || $(INSTALL_DATA) etc/honeytrap.conf.dist $(DESTDIR)/$(sysconfdir)/honeytrap/honeytrap.conf
	$(INSTALL_DATA) etc/ports.conf.dist $(DESTDIR)/$(sysconfdir)/honeytrap/ports.conf.dist
	$(INSTALL_DATA) etc/responses/* $(DESTDIR)/$(sysconfdir)/honeytrap/responses
