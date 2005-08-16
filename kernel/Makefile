#
# Makefile for the Linux kernel device drivers.
#

EXTRA_CFLAGS += -I$(obj) -I$(obj)/../include -DNETLINK_STGT=12

ifneq ($(KERNELRELEASE),)
obj-m		+= stgt.o
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
