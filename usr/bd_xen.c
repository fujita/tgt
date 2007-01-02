/*
 * Xen file backed routine
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
#include <sys/uio.h>

#include "list.h"
#include "util.h"
#include "tgtd.h"

#define O_DIRECT 040000 /* who defines this?*/

static int bd_xen_open(struct tgt_device *dev, char *path, int *fd, uint64_t *size)
{
	*fd = backed_file_open(path, O_RDWR| O_LARGEFILE | O_DIRECT, size);

	return *fd >= 0 ? 0 : *fd;
}

static void bd_xen_close(struct tgt_device *dev)
{
	close(dev->fd);
}

/*
 * Replace this with AIO readv/writev after 2.6.20.
 */
static int bd_xen_cmd_submit(struct tgt_device *dev, uint8_t *scb, int rw,
			     uint32_t datalen, unsigned long *uaddr,
			     uint64_t offset, int *async, void *key)
{
	struct iovec *iov = (struct iovec *) (void *) *uaddr;
	int cnt;
	long total;

	cnt = total = 0;
	do {
		total += iov[cnt++].iov_len;
	} while (total < datalen);

	lseek64(dev->fd, offset, SEEK_SET);

	if (rw == READ)
		readv(dev->fd, iov, cnt);
	else
		writev(dev->fd, iov, cnt);

	return 0;
}

static int bd_xen_cmd_done(int do_munmap, int do_free, uint64_t uaddr, int len)
{
	return 0;
}

struct backedio_template xen_bdt = {
	.bd_open		= bd_xen_open,
	.bd_close		= bd_xen_close,
	.bd_cmd_submit		= bd_xen_cmd_submit,
	.bd_cmd_done		= bd_xen_cmd_done,
};
