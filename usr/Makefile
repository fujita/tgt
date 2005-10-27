CFLAGS += -O2 -fno-inline -Wall -Wstrict-prototypes -I../include -DNETLINK_TGT=20
PROGRAMS = tgtd tgtadm scsi.so

all: $(PROGRAMS)

tgtd: tgtd.o netlink.o ipc.o dl.o log.o
	$(CC) -rdynamic -ldl $^ -o $@

tgtadm: tgtadm.o
	$(CC) -rdynamic -ldl $^ -o $@

scsi.so: scsi.o
	$(CC) -shared -o $@ $^

clean:
	rm -f *.o $(PROGRAMS)
