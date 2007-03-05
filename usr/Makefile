ifneq ($(XEN),)
XEN_ROOT = ../..
include $(XEN_ROOT)/tools/Rules.mk
LINUX_ROOT := $(wildcard $(XEN_ROOT)/linux-2.6.*-xen)
INCLUDES += -I$(XEN_LIBXC) -I$(XEN_XENSTORE) -I$(XEN_ROOT)/xen/include
INCLUDES += -I$(LINUX_ROOT)/include -I.
LIBAIO_DIR = ../libaio/src
AIOLIBS := $(LIBAIO_DIR)/libaio.a
CFLAGS += -I$(XEN_LIBXC) -I$(LIBAIO_DIR)
CFLAGS += $(INCLUDES) -I. -I../../xenstore 
CFLAGS += -DXEN -DUSE_KERNEL
LIBS := -L. -L.. -L../lib
LIBS += -L$(XEN_LIBXC)
LIBS += -lxenctrl
LIBS += -L$(XEN_XENSTORE) -lxenstore $(AIOLIBS)
TGTD_OBJS += $(addprefix xen/, xen.o xs_api.o xenbus.o)
TGTD_OBJS += tgtif.o bd_xen.o
else
INCLUDES += -I../include -I$(KERNELSRC)/include
LIBS += -laio
endif

ifneq ($(SGV4),)
TGTD_OBJS += spt_sgv4.o
else
TGTD_OBJS += spt_sgv3.o
endif

ifneq ($(IBMVIO),)
CFLAGS += -DIBMVIO -DUSE_KERNEL
TGTD_OBJS += $(addprefix ibmvio/, ibmvio.o)
TGTD_OBJS += bd_mmap.o tgtif.o
BD_MMAP=1
endif

ifneq ($(ISCSI),)
CFLAGS += -DISCSI
TGTD_OBJS += $(addprefix iscsi/, conn.o param.o session.o iscsid.o target.o \
	chap.o transport.o iscsi_tcp.o)
TGTD_OBJS += bd_aio.o
LIBS += -lcrypto -lpthread
BD_AIO=1
endif

INCLUDES += -I.
CFLAGS += -Wall -g -O2 -Wstrict-prototypes -fPIC -D_LARGEFILE64_SOURCE $(INCLUDES)

PROGRAMS += tgtd tgtadm
TGTD_OBJS += tgtd.o mgmt.o target.o spc.o sbc.o mmc.o osd.o spt.o scsi.o log.o \
	driver.o util.o work.o

all: $(PROGRAMS)

tgtd: $(TGTD_OBJS)
	$(CC) $^ -o $@ $(LIBS)

tgtadm: tgtadm.o
	$(CC) $^ -o $@

ifneq ($(XEN),)
install: $(PROGRAMS)
	install -m 0755 $(PROGRAMS) $(DESTDIR)/usr/sbin
endif

clean:
	rm -f *.o $(PROGRAMS) iscsi/*.o ibmvio/*.o xen/*.o
