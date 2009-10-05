SCRIPTS += tgt-setup-lun tgt-admin

.PHONY: all
all:

.PHONY: install
install: $(SCRIPTS)
	install -d -m 755 $(DESTDIR)/usr/sbin
	install -m 755 $(SCRIPTS) $(DESTDIR)/usr/sbin

.PHONY: clean
clean:

