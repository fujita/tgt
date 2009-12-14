mandir ?= $(PREFIX)/share/man
docdir ?= $(PREFIX)/share/doc/tgt

MANPAGES = manpages/tgtadm.8 manpages/tgt-admin.8 \
		manpages/tgt-setup-lun.8
DOCS = README.fcoe README.ibmvstgt README.iscsi README.iser \
	    README.lu_configuration README.mmc tmf.txt

.PHONY:all
all:

.PHONY: install
install: $(MANPAGES) $(DOCS)
	install -d -m 755 $(DESTDIR)$(mandir)/man8
	install -m 644 $(MANPAGES) $(DESTDIR)$(mandir)/man8
	install -d -m 755 $(DESTDIR)$(docdir)
	install -m 644 $(DOCS) $(DESTDIR)$(docdir)

.PHONY: clean
clean:

