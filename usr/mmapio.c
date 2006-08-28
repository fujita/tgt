#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

#include "list.h"
#include "util.h"
#include "tgtd.h"

static void *mmapio_cmd_buffer_alloc(int devio, uint32_t datalen)
{
	void *data = NULL;
	if (!devio) {
		datalen = ALIGN(datalen, PAGE_SIZE);
		data = valloc(datalen);
		if (data)
			memset(data, 0, datalen);
	}
	return data;
}

static int mmapio_cmd_submit(struct tgt_device *dev, int rw, uint32_t datalen,
			     unsigned long *uaddr, uint64_t offset)
{
	int fd = dev->fd;
	void *p;
	int err = 0;

	if (*uaddr)
		*uaddr = *uaddr + offset;
	else {
		p = mmap64(NULL, pgcnt(datalen, offset) << PAGE_SHIFT,
			   PROT_READ | PROT_WRITE, MAP_SHARED, fd,
			   offset & ~((1ULL << PAGE_SHIFT) - 1));

		*uaddr = (unsigned long) p + (offset & ~PAGE_MASK);
		if (p == MAP_FAILED) {
			err = -EINVAL;
			eprintf("%lx %u %" PRIu64 "\n", *uaddr, datalen, offset);
		}
	}

	printf("%lx %u %" PRIu64 "\n", *uaddr, datalen, offset);

	return err;
}

static int mmapio_cmd_done(int do_munmap, int do_free, uint64_t uaddr, int len)
{
	int err = 0;

	dprintf("%d %d %" PRIx64 " %d\n", do_munmap, do_free, uaddr, len);

	if (do_munmap) {
		len = pgcnt(len, (uaddr & ~PAGE_MASK)) << PAGE_SHIFT;
		uaddr &= PAGE_MASK;
		err = munmap((void *) (unsigned long) uaddr, len);
		if (err)
			eprintf("%" PRIx64 " %d\n", uaddr, len);
	} else if (do_free)
		free((void *) (unsigned long) uaddr);

	return err;
}

struct backedio_operations mmapio = {
	.bd_cmd_buffer_alloc	= mmapio_cmd_buffer_alloc,
	.bd_cmd_submit		= mmapio_cmd_submit,
	.bd_cmd_done		= mmapio_cmd_done,
};
