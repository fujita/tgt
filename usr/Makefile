sbindir ?= $(PREFIX)/sbin

ifneq ($(shell test -e /usr/include/linux/signalfd.h && echo 1),)
CFLAGS += -DUSE_SIGNALFD
endif

ifneq ($(shell test -e /usr/include/sys/timerfd.h && echo 1),)
CFLAGS += -DUSE_TIMERFD
endif

ifneq ($(IBMVIO),)
CFLAGS += -DIBMVIO -DUSE_KERNEL
TGTD_OBJS += $(addprefix ibmvio/, ibmvio.o)
TGTD_OBJS += bs_mmap.o tgtif.o
endif

TGTD_OBJS += $(addprefix iscsi/, conn.o param.o session.o \
		iscsid.o target.o chap.o sha1.o md5.o transport.o iscsi_tcp.o \
		isns.o)
TGTD_OBJS += bs_rdwr.o bs_aio.o

ifneq ($(ISCSI_RDMA),)
CFLAGS += -DISCSI_RDMA
TGTD_OBJS += iscsi/iser.o iscsi/iser_text.o
LIBS += -libverbs -lrdmacm
endif

ifneq ($(FCP),)
CFLAGS += -DFCP -DUSE_KERNEL
TGTD_OBJS += $(addprefix fc/, fc.o)
TGTD_OBJS += bs_mmap.o tgtif.o
endif

ifneq ($(FCOE),)
TGTD_OBJS += $(addprefix fcoe/,\
	openfc_target.o \
	openfc_scst.o \
	fcs_state.o \
	fc_exch.o \
	fc_disc_targ.o \
	fc_frame.o \
	fc_local_port.o \
	fc_remote_port.o \
	fc_sess.o \
	fc_virt_fab.o \
	fc_port.o \
	fcoe_if.o fcoe_dev.o \
	sa_event.o sa_timer.o sa_hash_kern.o sa_state.o\
	crc32_le.o crc32_le_tab.o)
TGTD_OBJS += bs_rdwr.o
endif

INCLUDES += -I.

CFLAGS += -D_GNU_SOURCE
CFLAGS += $(INCLUDES)
ifneq ($(DEBUG),)
CFLAGS += -g -O0 -ggdb -rdynamic
else
CFLAGS += -g -O2 -fno-strict-aliasing
endif
CFLAGS += -Wall -Wstrict-prototypes -fPIC
CFLAGS += -DTGT_VERSION=\"$(VERSION)$(EXTRAVERSION)\"

LIBS += -lpthread

PROGRAMS += tgtd tgtadm tgtimg
TGTD_OBJS += tgtd.o mgmt.o target.o scsi.o log.o driver.o util.o work.o \
		parser.o spc.o sbc.o mmc.o osd.o scc.o smc.o \
		ssc.o bs_ssc.o libssc.o \
		bs_null.o bs_sg.o bs.o libcrc32c.o

TGTD_DEP = $(TGTD_OBJS:.o=.d)

.PHONY:all
all: $(PROGRAMS)

tgtd: $(TGTD_OBJS)
	$(CC) $^ -o $@ $(LIBS)

-include $(TGTD_DEP)

tgtadm: tgtadm.o
	$(CC) $^ -o $@

-include tgtadm.d

tgtimg: tgtimg.o libssc.o libcrc32c.o
	$(CC) $^ -o $@

-include tgtimg.d libssc.d

%.o: %.c
	$(CC) -c $(CFLAGS) $*.c -o $*.o
	@$(CC) -MM $(CFLAGS) -MF $*.d -MT $*.o $*.c

.PHONY: install
install: $(PROGRAMS)
	install -d -m 755 $(DESTDIR)$(sbindir)
	install -m 755 $(PROGRAMS) $(DESTDIR)$(sbindir)

.PHONY: clean
clean:
	rm -f *.[od] $(PROGRAMS) iscsi/*.[od] ibmvio/*.[od] fc/*.[od] fcoe/*.[od]
