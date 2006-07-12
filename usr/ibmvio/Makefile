CFLAGS += -O2 -fno-inline -Wall -fPIC -Wstrict-prototypes -I$(KERNELSRC)/include -I../../usr
OBJS = libibmvstgt.o
SHAREDLIB = libibmvstgt.so

$(SHAREDLIB): $(OBJS)
	$(CC) -shared -o $@ $(OBJS)

clean:
	rm -f *.o $(PROGRAMS) $(SHAREDLIB)
