sbindir ?= $(PREFIX)/sbin
libdir ?= $(PREFIX)/lib/tgt

ifneq ($(shell test -e /usr/include/linux/signalfd.h && echo 1),)
CFLAGS += -DUSE_SIGNALFD
endif

ifneq ($(shell test -e /usr/include/sys/timerfd.h && echo 1),)
CFLAGS += -DUSE_TIMERFD
endif

TGTD_OBJS += $(addprefix iscsi/, conn.o param.o session.o \
		iscsid.o target.o chap.o sha1.o md5.o transport.o iscsi_tcp.o \
		isns.o)

ifneq ($(CEPH_RBD),)
MODULES += bs_rbd.so
endif

ifneq ($(shell test -e /usr/include/sys/eventfd.h && test -e /usr/include/libaio.h && echo 1),)
CFLAGS += -DUSE_EVENTFD
TGTD_OBJS += bs_aio.o
LIBS += -laio
endif

ifneq ($(ISCSI_RDMA),)
TGTD_OBJS += iscsi/iser.o iscsi/iser_text.o
LIBS += -libverbs -lrdmacm
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
CFLAGS += -DBSDIR=\"$(DESTDIR)$(libdir)/backing-store\"

LIBS += -lpthread -ldl

PROGRAMS += tgtd tgtadm tgtimg
TGTD_OBJS += tgtd.o mgmt.o target.o scsi.o log.o driver.o util.o work.o \
		concat_buf.o parser.o spc.o sbc.o mmc.o osd.o scc.o smc.o \
		ssc.o libssc.o bs_rdwr.o bs_ssc.o \
		bs_null.o bs_sg.o bs.o libcrc32c.o bs_sheepdog.o

TGTD_DEP = $(TGTD_OBJS:.o=.d)

LDFLAGS = -Wl,-E,-rpath=$(libdir)

.PHONY:all
all: $(PROGRAMS) $(MODULES)

tgtd: $(TGTD_OBJS)
	echo $(CC) $^ -o $@ $(LIBS)
	$(CC) $^ -o $@ $(LDFLAGS) $(LIBS)

-include $(TGTD_DEP)

TGTADM_OBJS = tgtadm.o concat_buf.o
TGTADM_DEP = $(TGTADM_OBJS:.o=.d)

tgtadm: $(TGTADM_OBJS)
	$(CC) $^ -o $@

-include $(TGTADM_DEP)

TGTIMG_OBJS = tgtimg.o libssc.o libcrc32c.o
TGTIMG_DEP = $(TGTIMG_OBJS:.o=.d)

tgtimg: $(TGTIMG_OBJS)
	$(CC) $^ -o $@

-include $(TGTIMG_DEP)

%.o: %.c
	$(CC) -c $(CFLAGS) $*.c -o $*.o
	@$(CC) -MM $(CFLAGS) -MF $*.d -MT $*.o $*.c

%.so: %.c
	$(CC) -shared $(CFLAGS) $*.c -o $*.so

bs_rbd.so: bs_rbd.c
	$(CC) -shared $(CFLAGS) bs_rbd.c -o bs_rbd.so -lrados -lrbd

.PHONY: install
install: $(PROGRAMS) $(MODULES)
	install -d -m 755 $(DESTDIR)$(sbindir)
	install -m 755 $(PROGRAMS) $(DESTDIR)$(sbindir)
ifneq ($(MODULES),)
	install -d -m 755 $(DESTDIR)$(libdir)/backing-store
	install -m 755 $(MODULES) $(DESTDIR)$(libdir)/backing-store
endif

.PHONY: clean
clean:
	rm -f *.[od] *.so $(PROGRAMS) iscsi/*.[od] ibmvio/*.[od] fc/*.[od]
