#
# Makefile for the Linux kernel device drivers.
#

EXTRA_CFLAGS += -I$(obj) -I$(obj)/../include -DNETLINK_STGT=20

ifneq ($(KERNELRELEASE),)
obj-m		+= stgt_core.o
stgt_core-objs	:= stgt_sysfs.o stgt.o

obj-m		+= stgt_sd.o stgt_vsd.o
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
