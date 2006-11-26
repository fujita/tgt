/*
 * AIO file backed routine
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
#include <libaio.h>

#include <linux/fs.h>
#include <sys/epoll.h>

#include "list.h"
#include "util.h"
#include "tgtd.h"

/*
 * We need an interface to wait for both synchronous and asynchronous
 * descriptors (something like BSD's kqueue). Now we use a kernel
 * patch to return an fd associated with the AIO context because Xen
 * blktap uses it (so we avoid introducing another patch). However,
 * I'm not sure the patch will go into mainline. Another approach,
 * IO_CMD_EPOLL_WAIT, looks more promising. kqueue is promising too.
 */

/* FIXME */
#define MAX_AIO_REQS 1024
#define O_DIRECT 040000 /* who defines this?*/

struct bd_aio_info {
	/* TODO: batch requests */
	struct iocb iocb[MAX_AIO_REQS];
	struct io_event events[MAX_AIO_REQS];
};

extern io_context_t ctx;

static int bd_aio_open(struct tgt_device *dev, char *path, int *fd, uint64_t *size)
{
	*fd = backed_file_open(path, O_RDWR| O_LARGEFILE, size);

	return *fd >= 0 ? 0 : *fd;
}

static void bd_aio_close(struct tgt_device *dev)
{
	tgt_event_del(dev->fd);
	close(dev->fd);
}

static int bd_aio_cmd_submit(struct tgt_device *dev, uint8_t *scb, int rw,
			     uint32_t datalen, unsigned long *uaddr,
			     uint64_t offset, int *async, void *key)
{
	struct iocb iocb, *io;
	int err;

	*async = 1;

	io = &iocb;
	memset(io, 0, sizeof(*io));

	dprintf("%d %d %u %lx %" PRIx64 " %p %p\n", dev->fd, rw, datalen, *uaddr, offset,
		io, key);

	if (rw == READ)
		io_prep_pread(io, dev->fd, (void *) *uaddr, datalen, offset);
	else
		io_prep_pwrite(io, dev->fd, (void *) *uaddr, datalen, offset);

	io->data = key;
	err = io_submit(ctx, 1, &io);

	return 0;
}

static int bd_aio_cmd_done(int do_munmap, int do_free, uint64_t uaddr, int len)
{
	return 0;
}

struct backedio_template aio_bdt = {
	.bd_datasize		= sizeof(struct bd_aio_info),
	.bd_open		= bd_aio_open,
	.bd_close		= bd_aio_close,
	.bd_cmd_submit		= bd_aio_cmd_submit,
	.bd_cmd_done		= bd_aio_cmd_done,
};
