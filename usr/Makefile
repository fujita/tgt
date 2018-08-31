sbindir ?= $(PREFIX)/sbin
libdir ?= $(PREFIX)/lib/tgt

CFLAGS += -fPIC

ifneq ($(shell test -e /usr/include/linux/signalfd.h && echo 1),)
CFLAGS += -DUSE_SIGNALFD
endif

ifneq ($(shell test -n $(shell find /usr/include -name "timerfd.h" | head -n1) && echo 1),)
CFLAGS += -DUSE_TIMERFD
endif

TGTD_OBJS += $(addprefix iscsi/, conn.o param.o session.o \
		iscsid.o target.o chap.o sha1.o md5.o transport.o iscsi_tcp.o \
		isns.o)

ifneq ($(CEPH_RBD),)
MODULES += bs_rbd.so
endif

ifneq ($(GLFS_BD),)
MODULES += bs_glfs.so
endif

ifneq ($(SD_NOTIFY),)
CFLAGS += -DUSE_SYSTEMD
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
INCLUDES +=-I/usr/local/include/hyc/include/
INCLUDES += -I/$(TGT_DIR)/thirdparty/ha-lib/src/
INCLUDES += -I/$(TGT_DIR)/thirdparty/ha-lib/third-party/include/

CFLAGS += -D_GNU_SOURCE
CFLAGS += $(INCLUDES)

ifneq ($(DEBUG),)
CFLAGS += -g -O0 -ggdb -rdynamic
CFLAGS += -fsanitize=address
else
CFLAGS += -g -O2 -fno-strict-aliasing
endif
CFLAGS += -Wall -Werror -fPIC
CFLAGS += -DTGT_VERSION=\"$(VERSION)$(EXTRAVERSION)\"
CFLAGS += -DBSDIR=\"$(DESTDIR)$(libdir)/backing-store\"


LIBS_GRP_START += -Wl,--start-group
LIBS_GRP_END += -Wl,--end-group
HYC_LIBS += -lHycClientLib -lStorRpcLib -lHycStorCommon
FOLLY_LIBS += -lfolly -lglog -lstdc++ -lm -levent -ldouble-conversion -liberty
C++_LIBS += -lstdc++ -lboost_system -lboost_context -lboost_thread
COMPRESSION_LIBS += -lz -lsnappy -llz4 -llzma -lzstd -lbz2
MISC_LIBS += -lpthread -ldl -lgflags -lcrypto -lssl
THRIFT_LIBS += -lthrift-core -lprotocol -lconcurrency -ltransport -lasync
THRIFT_LIBS += -lsecurity -lserver -lthriftfrozen2 -lthriftprotocol
THRIFT_LIBS += -lthriftcpp2 -lwangle -latomic

HA_DEP_LIBS += -lbase64 -lcurl -ljansson -lmicrohttpd -lorcania -lulfius -lyder
HA_LIB += -lha $(HA_DEP_LIBS)

LIBS += $(LIBS_GRP_START) $(HYC_LIBS) $(FOLLY_LIBS) $(THRIFT_LIBS) $(C++_LIBS)
LIBS += $(COMPRESSION_LIBS) $(MISC_LIBS) $(HA_LIB) $(LIBS_GRP_END)

ASAN_LIB :=
ifneq ($(DEBUG), )
ASAN_LIB = -lasan
LIBS += $(ASAN_LIB)
endif

ifneq ($(SD_NOTIFY),)
LIBS += -lsystemd
endif

PROGRAMS += tgtd tgtadm tgtimg
TGTD_OBJS += tgtd.o mgmt.o target.o scsi.o log.o driver.o util.o work.o \
		concat_buf.o parser.o spc.o sbc.o mmc.o osd.o scc.o smc.o \
		ssc.o libssc.o bs_rdwr.o bs_ssc.o \
		bs_null.o bs_sg.o bs.o libcrc32c.o bs_sheepdog.o bs_hyc.o

TGTD_DEP = $(TGTD_OBJS:.o=.d)

LDFLAGS = -Wl,-E,-rpath=$(libdir)
LDFLAGS += -L/usr/lib/hyc -L/$(TGT_DIR)/thirdparty/ha-lib/build/src/
LDFLAGS += -L$(TGT_DIR)/thirdparty/ha-lib/third-party/lib

.PHONY:all
all: $(PROGRAMS) $(MODULES)

tgtd: $(TGTD_OBJS)
	echo $(CC) $^ -o $@ $(LIBS)
	$(CC) $^ -o $@ $(LDFLAGS) $(LIBS)

-include $(TGTD_DEP)

TGTADM_OBJS = tgtadm.o concat_buf.o
TGTADM_DEP = $(TGTADM_OBJS:.o=.d)

tgtadm: $(TGTADM_OBJS)
	$(CC) $^ -o $@ $(ASAN_LIB)

-include $(TGTADM_DEP)

TGTIMG_OBJS = tgtimg.o libssc.o libcrc32c.o
TGTIMG_DEP = $(TGTIMG_OBJS:.o=.d)

tgtimg: $(TGTIMG_OBJS)
	$(CC) $^ -o $@ $(ASAN_LIB)

-include $(TGTIMG_DEP)

%.o: %.c
	$(CC) -c $(CFLAGS) $*.c -o $*.o
	@$(CC) -MM $(CFLAGS) -MF $*.d -MT $*.o $*.c

%.so: %.c
	$(CC) -shared $(CFLAGS) $*.c -o $*.so

bs_rbd.so: bs_rbd.c
	$(CC) -shared $(CFLAGS) bs_rbd.c -o bs_rbd.so -lrados -lrbd

bs_glfs.so: bs_glfs.c
	$(CC) -I/usr/include/glusterfs/api -shared $(CFLAGS) bs_glfs.c -o bs_glfs.so -lgfapi

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
