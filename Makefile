#KERNELSRC := /usr/src/linux

ifeq ($(KERNELSRC),)
	KERNELSRC ?= /lib/modules/$(shell uname -r)/build
endif

export KERNELSRC

all:
	make -C istgt

	make -C usr
	make -C kernel
clean:
	make -C usr clean
	make -C kernel clean

	make -C istgt clean
