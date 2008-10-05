# LIBS := -L. -L.. -L../lib
INCLUDES += -I../include -I../usr

INCLUDES += -I.
CFLAGS += -Wall -g -O2 -Wstrict-prototypes -fPIC -D_LARGEFILE64_SOURCE $(INCLUDES)

PROGRAMS += mktape dump_tape
MKTAPE_OBJS += mktape.o
DUMP_TAPE_OBJS += dump_tape.o

.PHONY: all
all: $(PROGRAMS)

mktape: $(MKTAPE_OBJS)
	$(CC) $^ -o $@ $(LIBS)

-include mktape.d

dump_tape: $(DUMP_TAPE_OBJS)
	$(CC) $^ -o $@ $(LIBS)

-include dump_tape.d

%.o: %c
	$(CC) -c $(CFLAGS) $*.c -o $*.o
	@$(CC) -MM $(CFLAGS) -MF $*.d -MT $*.o $*.c

.PHONY: install
install: $(PROGRAMS)
	install -m 0755 $(PROGRAMS) $(DESTDIR)/usr/bin

.PHONY: clean
clean:
	rm -f *.o $(PROGRAMS)
