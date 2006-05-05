CFLAGS += -O2 -fno-inline -Wall -fPIC -Wstrict-prototypes -I$(KERNELSRC)/include -I../include -I../../include -I../../usr
LIBS = -lcrypto
OBJS = libistgt.o
SHAREDLIB = libistgt.so
DAEMON = istgtd

all: $(DAEMON) $(SHAREDLIB)

$(DAEMON): log.o istgt.o conn.o param.o session.o iscsid.o target.o chap.o netlink.o
	$(CC) $^ -o $@ $(LIBS)

$(SHAREDLIB): $(OBJS)
	$(CC) -shared -o $@ $(OBJS)

clean:
	rm -f *.o istgtd $(SHAREDLIB)
