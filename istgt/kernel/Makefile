#
# Makefile for the Linux kernel device drivers.
#
# Note! Dependencies are done automagically by 'make dep', which also
# removes any old dependencies. DON'T put your own dependencies here
# unless it's something special (not a .c file).
#
# Note 2! The CFLAGS definitions are now in the main makefile.

EXTRA_CFLAGS += -I$(obj) -I$(obj)/../include -I$(obj)/../../kernel

ifneq ($(KERNELRELEASE),)
obj-m		+= istgt.o
istgt-objs	:= iscsi.o nthread.o config.o digest.o\
			conn.o session.o target.o param.o
else

ifeq ($(KERNELSRC),)
	KERNELSRC ?= /lib/modules/$(shell uname -r)/build
endif

PWD := $(shell pwd)

default:
	$(MAKE) -C $(KERNELSRC) SUBDIRS=$(PWD) modules

clean:
	$(MAKE) -C $(KERNELSRC) SUBDIRS=$(PWD) clean
endif


