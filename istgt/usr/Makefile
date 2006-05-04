CFLAGS += -O2 -fno-inline -Wall -fPIC -Wstrict-prototypes -I$(KERNELSRC)/include -I../include -I../../include -I../../usr
LIBS = -lcrypto
OBJS = param.o iscsid.o session.o target.o chap.o ctldev.o
SHAREDLIB = istgt.so
DAEMON = istgtd

$(DAEMON): log.o istgt.o conn.o param.o session.o iscsid.o target.o chap.o ctldev.o
	$(CC) $^ -o $@ $(LIBS)

$(SHAREDLIB): $(OBJS)
	$(CC) -shared -o $@ $(OBJS)

clean:
	rm -f *.o istgtd $(SHAREDLIB)
