VERSION ?= 1.0.2

# Define a common prefix where binaries and docs install
PREFIX ?= /usr

# Export VERSION and PREFIX so sub-make knows about them
export VERSION PREFIX

# Export the feature switches so sub-make knows about them
export ISCSI ISCSI_RDMA IBMVIO FCOE FCP

.PHONY: all
all: programs doc conf scripts

# Targets for the /usr/sbin utilities
.PHONY: programs install-programs clean-programs
programs:
	$(MAKE) -C usr

install-programs:
	$(MAKE) -C usr install

clean-programs:
	$(MAKE) -C usr clean

# Targets for man pages and other documentation
.PHONY: doc install-doc clean-doc
doc:
	$(MAKE) -C doc

install-doc:
	$(MAKE) -C doc install

clean-doc:
	$(MAKE) -C doc clean

# Targets for scripts
.PHONY: scripts install-scripts clean-scripts
scripts:
	$(MAKE) -C scripts

install-scripts:
	$(MAKE) -C scripts install

clean-scripts:
	$(MAKE) -C scripts clean


# Targets for configuration stubs
.PHONY: conf install-conf clean-conf
conf:
	$(MAKE) -C conf

install-conf:
	$(MAKE) -C conf install

clean-conf:
	$(MAKE) -C conf clean

.PHONY: install
install: install-programs install-doc install-conf install-scripts

.PHONY: clean
clean: clean-programs clean-doc clean-conf clean-scripts
