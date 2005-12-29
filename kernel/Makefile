#
# Makefile for the Linux kernel device drivers.
#

EXTRA_CFLAGS += -I$(obj) -I$(obj)/../include -DNETLINK_TGT=20

ifneq ($(KERNELRELEASE),)
obj-m		+= tgt_core.o
tgt_core-objs	:= tgt.o tgt_nl.o tgt_sysfs.o tgt_protocol.o

obj-m		+= tgt_scsi.o
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
