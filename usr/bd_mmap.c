/*
 * mmap file backed routine
 *
 * Copyright (C) 2006 FUJITA Tomonori <tomof@acm.org>
 * Copyright (C) 2006 Mike Christie <michaelc@cs.wisc.edu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */
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

static struct tgt_device *bd_mmap_open(char *path, int *fd, uint64_t *size)
{
	struct tgt_device *dev;

	dev = zalloc(sizeof(*dev));
	if (!dev)
		return NULL;

	*fd = backed_file_open(path, O_RDWR| O_LARGEFILE, size);
	if (*fd < 0) {
		free(dev);
		dev = NULL;
	}

	return dev;
}

static void bd_mmap_close(struct tgt_device *dev)
{
	free(dev);
}

static void *bd_mmap_cmd_buffer_alloc(int devio, uint32_t datalen)
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

static int bd_mmap_cmd_submit(struct tgt_device *dev, int rw, uint32_t datalen,
			      unsigned long *uaddr, uint64_t offset, int *async,
			      void *key)
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

static int bd_mmap_cmd_done(int do_munmap, int do_free, uint64_t uaddr, int len)
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

struct backedio_template mmap_bdt = {
	.bd_open		= bd_mmap_open,
	.bd_close		= bd_mmap_close,
	.bd_cmd_buffer_alloc	= bd_mmap_cmd_buffer_alloc,
	.bd_cmd_submit		= bd_mmap_cmd_submit,
	.bd_cmd_done		= bd_mmap_cmd_done,
};
