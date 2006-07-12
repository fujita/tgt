CFLAGS += -O2 -fno-inline -Wall -fPIC -Wstrict-prototypes -I$(KERNELSRC)/include -I../../istgt/include -I../../include -I../../usr
LIBS = -lcrypto
DAEMON = iscsi.o

$(DAEMON): istgt.o conn.o param.o session.o iscsid.o target.o chap.o netlink.o
	$(CC) -o $@ $^ $(LIBS)

clean:
	rm -f *.o istgtd $(SHAREDLIB)
