mandir ?= $(PREFIX)/share/man
docdir ?= $(PREFIX)/share/doc/tgt

MANPAGES = manpages/tgtadm.8 manpages/tgt-admin.8 manpages/tgtimg.8 \
		manpages/tgt-setup-lun.8 manpages/tgtd.8

DOCS = README.fcoe README.ibmvstgt README.iscsi README.iser \
	    README.lu_configuration README.mmc tmf.txt

XSLTPROC = /usr/bin/xsltproc
XMLMAN = manpages/tgtd.8 manpages/tgtadm.8 manpages/tgtimg.8
XMLHTML = htmlpages/tgtd.8.html htmlpages/tgtadm.8.html \
		htmlpages/tgtimg.8.html

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

manpages/tgtd.8: tgtd.8.xml
	-test -z "$(XSLTPROC)" || $(XSLTPROC) -o $@ http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $<

htmlpages/tgtd.8.html: tgtd.8.xml
	-test -z "$(XSLTPROC)" || $(XSLTPROC) -o $@ http://docbook.sourceforge.net/release/xsl/current/html/docbook.xsl $<

manpages/tgtadm.8: tgtadm.8.xml
	-test -z "$(XSLTPROC)" || $(XSLTPROC) -o $@ http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $<

htmlpages/tgtadm.8.html: tgtadm.8.xml
	-test -z "$(XSLTPROC)" || $(XSLTPROC) -o $@ http://docbook.sourceforge.net/release/xsl/current/html/docbook.xsl $<

manpages/tgtimg.8: tgtimg.8.xml
	-test -z "$(XSLTPROC)" || $(XSLTPROC) -o $@ http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $<

htmlpages/tgtimg.8.html: tgtimg.8.xml
	-test -z "$(XSLTPROC)" || $(XSLTPROC) -o $@ http://docbook.sourceforge.net/release/xsl/current/html/docbook.xsl $<

xmlman: $(XMLMAN)

xmlhtml: $(XMLHTML)

