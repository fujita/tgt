CFLAGS += -O2 -fno-inline -Wall -Wstrict-prototypes -I../include -DNETLINK_STGT=20
PROGRAMS = stgtd

all: $(PROGRAMS)

stgtd: stgtd.o scsi.o ipc.o
	$(CC) $^ -o $@ $(LIBS)

clean:
	rm -f *.o $(PROGRAMS)
