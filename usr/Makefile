CFLAGS += -O2 -fno-inline -Wall -Wstrict-prototypes -I../include -DNETLINK_TGT=20
PROGRAMS = tgtd tgtadm

all: $(PROGRAMS)

tgtd: tgtd.o scsi.o netlink.o ipc.o log.o
	$(CC) -rdynamic -ldl $^ -o $@

tgtadm: tgtadm.o
	$(CC) -rdynamic -ldl $^ -o $@
clean:
	rm -f *.o $(PROGRAMS)
