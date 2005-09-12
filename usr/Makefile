CFLAGS += -O2 -fno-inline -Wall -Wstrict-prototypes -I../include -DNETLINK_TGT=20
PROGRAMS = tgtd

all: $(PROGRAMS)

tgtd: tgtd.o scsi.o netlink.o ipc.o log.o
	$(CC) $^ -o $@ $(LIBS)

clean:
	rm -f *.o $(PROGRAMS)
