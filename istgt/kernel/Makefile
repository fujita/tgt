#
# Makefile for the Linux kernel device drivers.
#
# Note! Dependencies are done automagically by 'make dep', which also
# removes any old dependencies. DON'T put your own dependencies here
# unless it's something special (not a .c file).
#
# Note 2! The CFLAGS definitions are now in the main makefile.

EXTRA_CFLAGS += -I$(obj) -I$(obj)/../include

ifneq ($(KERNELRELEASE),)
obj-m				+= scsi_transport_iscsi.o
obj-m				+= libiscsi.o
obj-m				+= iscsi_tcp.o
obj-m				+= iscsi_tcp_tgt.o
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


