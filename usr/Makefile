CFLAGS += -O2 -fno-inline -Wall -Wstrict-prototypes -g -D_LARGEFILE64_SOURCE \
	-I$(KERNELSRC)/include -I../include -I.
PROGRAMS = tgtd tgtadm
TGTD_OBJS = tgtd.o mgmt.o target.o scsi.o log.o driver.o util.o sched.o
LIBS += -laio

ifneq ($(IBMVIO),)
CFLAGS += -DIBMVIO -DUSE_KERNEL
TGTD_OBJS += $(addprefix ibmvio/, ibmvio.o)
BD_MMAP=1
endif

ifneq ($(ISCSI),)
CFLAGS += -DISCSI
TGTD_OBJS += $(addprefix iscsi/, conn.o param.o session.o iscsid.o target.o \
	account.o chap.o transport.o)
TGTD_OBJS += $(addprefix iscsi/, iscsi_tcp.o)
LIBS += -lcrypto
BD_AIO=1
endif

ifneq ($(BD_MMAP),)
TGTD_OBJS += bd_mmap.o tgtif.o
endif

ifneq ($(BD_AIO),)
TGTD_OBJS += bd_aio.o
endif

all: $(PROGRAMS)

tgtd: $(TGTD_OBJS)
	$(CC) $^ -g -o $@ $(LIBS)

tgtadm: tgtadm.o
	$(CC) $^ -o $@

clean:
	rm -f *.o $(PROGRAMS) iscsi/*.o ibmvio/*.o
