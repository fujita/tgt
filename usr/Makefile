VERSION = 0.9.2
EXTRAVERSION = $(if $(shell git-show-ref 2>/dev/null),-git-$(shell git-show-ref --heads --abbrev|awk '/refs\/heads\/master/{print $$1}'))

mandir = /usr/share/man

ifneq ($(IBMVIO),)
CFLAGS += -DIBMVIO -DUSE_KERNEL
TGTD_OBJS += $(addprefix ibmvio/, ibmvio.o)
TGTD_OBJS += bs_mmap.o tgtif.o
endif

ifneq ($(ISCSI),)
CFLAGS += -DISCSI
TGTD_OBJS += $(addprefix iscsi/, conn.o param.o session.o \
		iscsid.o target.o chap.o transport.o iscsi_tcp.o \
		isns.o)
TGTD_OBJS += bs_rdwr.o bs_aio.o

LIBS += -lcrypto
ifneq ($(ISCSI_RDMA),)
CFLAGS += -DISCSI_RDMA
TGTD_OBJS += iscsi/iscsi_rdma.o
LIBS += -libverbs -lrdmacm
endif
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

INCLUDES += -I. -I../include -I$(KERNELSRC)/include

CFLAGS += -D_GNU_SOURCE
CFLAGS += $(INCLUDES)
CFLAGS += -g -O2 -Wall -Wstrict-prototypes -fPIC
CFLAGS += -DTGT_VERSION=\"$(VERSION)$(EXTRAVERSION)\"

LIBS += -lpthread

PROGRAMS += tgtd tgtadm mktape dump_tape
SCRIPTS += ../scripts/tgt-setup-lun ../scripts/tgt-admin
TGTD_OBJS += tgtd.o mgmt.o target.o scsi.o log.o driver.o util.o work.o \
		parser.o spc.o sbc.o mmc.o osd.o scc.o smc.o \
		ssc.o bs_ssc.o libssc.o \
		bs_null.o bs_sg.o bs.o libcrc32c.o
MANPAGES = ../doc/manpages/tgtadm.8 ../doc/manpages/tgt-admin.8 \
		../doc/manpages/tgt-setup-lun.8

TGTD_DEP = $(TGTD_OBJS:.o=.d)

.PHONY:all
all: $(PROGRAMS)

tgtd: $(TGTD_OBJS)
	$(CC) $^ -o $@ $(LIBS)

-include $(TGTD_DEP)

tgtadm: tgtadm.o
	$(CC) $^ -o $@

-include tgtadm.d

mktape: mktape.o libssc.o libcrc32c.o
	$(CC) $^ -o $@

-include mktape.d libssc.d

dump_tape: dump_tape.o libssc.o libcrc32c.o
	$(CC) $^ -o $@

-include dump_tape.d libssc.d

%.o: %.c
	$(CC) -c $(CFLAGS) $*.c -o $*.o
	@$(CC) -MM $(CFLAGS) -MF $*.d -MT $*.o $*.c

.PHONY: install
install: $(PROGRAMS) $(SCRIPTS) install_doc
	install -d -m 755 $(DESTDIR)/usr/sbin
	install -m 755 $(PROGRAMS) $(SCRIPTS) $(DESTDIR)/usr/sbin

install_doc: $(MANPAGES)
	install -d -m 755 $(DESTDIR)$(mandir)/man8
	install -m 644 $^ $(DESTDIR)$(mandir)/man8

.PHONY: clean
clean:
	rm -f *.[od] $(PROGRAMS) iscsi/*.[od] ibmvio/*.[od] fc/*.[od] fcoe/*.[od]
