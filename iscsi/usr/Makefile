CFLAGS += -O2 -fno-inline -Wall -Wstrict-prototypes -g -I../include
PROGRAMS = ietd ietadm
LIBS = -lcrypto

all: $(PROGRAMS)

ietd: ietd.o iscsid.o conn.o session.o target.o message.o ctldev.o log.o isns.o chap.o event.o param.o plain.o

	$(CC) $^ -o $@ $(LIBS)

ietadm: ietadm.o param.o
	$(CC) $^ -o $@

clean:
	rm -f *.o $(PROGRAMS)
