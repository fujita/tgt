#KERNELSRC := /usr/src/linux

ifeq ($(KERNELSRC),)
	KERNELSRC ?= /lib/modules/$(shell uname -r)/build
endif

export KERNELSRC

all:
ifeq ($(ARCH), ppc64)
	make -C ibmvstgt
endif
	make -C istgt

	make -C usr
	make -C kernel
clean:
	make -C usr clean
	make -C kernel clean

ifeq ($(ARCH), ppc64)
	make -C ibmvstgt clean
endif
	make -C istgt clean
