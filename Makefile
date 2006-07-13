#
# Need to use some magic to select what target drivers will be complied
#

IBMVIO=1
ISCSI=1

ifeq ($(KERNELSRC),)
	KERNELSRC ?= /lib/modules/$(shell uname -r)/build
endif

export IBMVIO
export ISCSI
export KERNELSRC

all:
ifeq ($(ARCH), powerpc)
	make -C ibmvstgt
else
	make -C istgt
endif
	make -C usr
	make -C kernel
clean:
	make -C usr clean
	make -C kernel clean

ifeq ($(ARCH), powerpc)
	make -C ibmvstgt clean
else
	make -C istgt clean
endif
