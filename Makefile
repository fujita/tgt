#
# Need to use some magic to select what target drivers will be complied
#

#IBMVIO=1
ISCSI=1

ifeq ($(KERNELSRC),)
	KERNELSRC ?= /lib/modules/$(shell uname -r)/build
endif

export IBMVIO
export ISCSI
export KERNELSRC

all:
	make -C usr

clean:
	make -C usr clean
