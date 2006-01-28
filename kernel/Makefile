#
# Makefile for the Linux kernel device drivers.
#

EXTRA_CFLAGS += -I$(obj) -I$(obj)/../include -DNETLINK_TGT=17 -DNETLINK_TGT_CMD=21

ifneq ($(KERNELRELEASE),)
obj-m			+= scsi_tgt_core.o
scsi_tgt_core-objs	:= scsi_tgt_lib.o scsi_tgt_nl.o

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
