EXTRA_CFLAGS += -I$(KERNELSRC)/drivers/scsi/ibmvscsi/

ifneq ($(KERNELRELEASE),)
obj-m		+= ibmvstgt.o

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
