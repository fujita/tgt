CFLAGS += -O2 -fno-inline -Wall -fPIC -Wstrict-prototypes -I$(KERNELSRC)/include -I../include -I../../include -I../../usr
#LIBS = -lcrypto
OBJS = conn.o param.o iscsid.o session.o target.o chap.o ctldev.o
SHAREDLIB = istgt.so
DAEMON = istgtd

$(DAEMON): istgt.o log.c
	$(CC) $^ -o $@

$(SHAREDLIB): $(OBJS)
	$(CC) -shared -o $@ $(OBJS)

clean:
	rm -f *.o $(PROGRAMS) $(SHAREDLIB)
