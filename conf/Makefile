sysconfdir ?= /etc

EXAMPLES = targets.conf.example targets.conf.vtl.L700 targets.conf.vtl.MSL2024

.PHONY: all
all:

.PHONY: install
install:
	install -d -m 755 $(DESTDIR)$(sysconfdir)/tgt
	if [ ! -f $(DESTDIR)$(sysconfdir)/tgt/targets.conf ] ; then \
		install -m 644 targets.conf $(DESTDIR)$(sysconfdir)/tgt ; \
	fi
	install -d -m 755 $(DESTDIR)$(sysconfdir)/tgt/examples
	for f in $(EXAMPLES) ; do \
		install -m 644 examples/$$f $(DESTDIR)$(sysconfdir)/tgt/examples ;\
	done
	install -d $(DESTDIR)$(sysconfdir)/tgt/conf.d

.PHONY: clean
clean:

