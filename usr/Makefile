ifneq ($(IBMVIO),)
CFLAGS += -DIBMVIO -DUSE_KERNEL
TGTD_OBJS += $(addprefix ibmvio/, ibmvio.o)
TGTD_OBJS += bs_mmap.o tgtif.o
endif

ifneq ($(ISCSI),)
CFLAGS += -DISCSI
TGTD_OBJS += $(addprefix iscsi/, conn.o param.o session.o \
		iscsid.o target.o chap.o transport.o iscsi_tcp.o \
		isns.o libcrc32c.o)
TGTD_OBJS += bs_rdwr.o
LIBS += -lcrypto -lpthread
endif

ifneq ($(FCP),)
CFLAGS += -DFCP -DUSE_KERNEL
TGTD_OBJS += $(addprefix fc/, fc.o)
TGTD_OBJS += bs_mmap.o tgtif.o
endif

INCLUDES += -I. -I../include -I$(KERNELSRC)/include

CFLAGS += -D_LARGEFILE64_SOURCE
CFLAGS += $(INCLUDES)
CFLAGS += -g -O2 -Wall -Wstrict-prototypes -fPIC

PROGRAMS += tgtd tgtadm
TGTD_OBJS += tgtd.o mgmt.o target.o scsi.o log.o driver.o util.o work.o \
		parser.o spc.o sbc.o mmc.o osd.o scc.o smc.o bs.o

TGTD_DEP = $(TGTD_OBJS:.o=.d)

.PHONY:all
all: $(PROGRAMS)

tgtd: $(TGTD_OBJS)
	$(CC) $^ -o $@ $(LIBS)

-include $(TGTD_DEP)

tgtadm: tgtadm.o
	$(CC) $^ -o $@

-include tgtadm.d

%.o: %.c
	$(CC) -c $(CFLAGS) $*.c -o $*.o
	@$(CC) -MM $(CFLAGS) -MF $*.d -MT $*.o $*.c

.PHONY: install
install: $(PROGRAMS)
	install -m 0755 $(PROGRAMS) $(DESTDIR)/usr/sbin

.PHONY: clean
clean:
	rm -f *.[od] $(PROGRAMS) iscsi/*.[od] ibmvio/*.[od] fc/*.[od]
