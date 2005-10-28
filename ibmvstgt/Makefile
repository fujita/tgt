#
# Makefile for the Linux kernel device drivers.
#
# Note! Dependencies are done automagically by 'make dep', which also
# removes any old dependencies. DON'T put your own dependencies here
# unless it's something special (not a .c file).
#
# Note 2! The CFLAGS definitions are now in the main makefile.

SUBDIRS := $(shell pwd)

all: mods

mods:
	$(MAKE) -C $(KERNELSRC) SUBDIRS=$(shell pwd)/kernel modules

libs:
	$(MAKE) -C usr

clean:
#	$(MAKE) -C usr clean
	$(MAKE) -C $(KERNELSRC) SUBDIRS=$(shell pwd)/kernel clean
