CFLAGS += -O2 -fno-inline -Wall -Wstrict-prototypes -fPIC -I$(KERNELSRC)/include -I../include
PROGRAMS = tgtd tgtadm

all: $(PROGRAMS)

tgtd: tgtd.o netlink.o dl.o mgmt.o target.o scsi.o log.o
	$(CC) -rdynamic -ldl $^ -o $@

tgtadm: tgtadm.o
	$(CC) -rdynamic -ldl $^ -o $@

clean:
	rm -f *.o $(PROGRAMS)
