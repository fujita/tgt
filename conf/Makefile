sysconfdir ?= /etc

EXAMPLES = targets.conf.example

.PHONY: all
all:

.PHONY: install
install:
	install -d -m 755 $(DESTDIR)$(sysconfdir)/tgt
	if [ ! -f $(DESTDIR)$(sysconfdir)/tgt/targets.conf ] ; then \
		install -m 644 targets.conf $(DESTDIR)$(sysconfdir)/tgt ; \
	fi
	install -d -m 755 $(DESTDIR)$(sysconfdir)/tgt/examples
	install -m 644 examples/$(EXAMPLES) $(DESTDIR)$(sysconfdir)/tgt/examples

.PHONY: clean
clean:

