SUBDIRS := $(shell pwd)

mods:
	$(MAKE) -C $(KERNELSRC) SUBDIRS=$(shell pwd)/kernel modules

clean:
	$(MAKE) -C $(KERNELSRC) SUBDIRS=$(shell pwd)/kernel clean
