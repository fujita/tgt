CFLAGS += -O2 -fno-inline -Wall -fPIC -Wstrict-prototypes -I../include -I../../include -I../../usr
#LIBS = -lcrypto
OBJS = istgt.o conn.o param.o iscsid.o session.o target.o chap.o ctldev.o
SHAREDLIB = istgt.so

$(SHAREDLIB): $(OBJS)
	$(CC) -shared -o $@ $(OBJS)

clean:
	rm -f *.o $(PROGRAMS) $(SHAREDLIB)
