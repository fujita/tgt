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
#include <pthread.h>

#include <linux/fs.h>
#include <sys/epoll.h>

#include "list.h"
#include "util.h"
#include "tgtd.h"

/*
 * We need an interface to wait for both synchronous and asynchronous
 * descriptors (something like BSD's kqueue). But upstream kernels
 * don't provide it though some candidates are under development. So
 * we use a hacky trick with pthread (stolen from RedHat Xen blktap
 * code).
 */

/* FIXME */
#define MAX_AIO_REQS 2048

struct bd_aio_info {
	io_context_t ctx;

	/* TODO: batch requests */
/* 	struct iocb iocb[MAX_AIO_REQS]; */
	struct io_event events[MAX_AIO_REQS];

	pthread_t aio_thread;

	int command_fd[2];
	int done_fd[2];
};

static void *bs_aio_endio_thread(void *arg)
{
	struct bd_aio_info *info = arg;
	int command, ret, nr;

retry:
	ret = read(info->command_fd[0], &command, sizeof(command));
	if (ret < 0) {
		eprintf("AIO pthread will be dead, %m\n");
		if (errno == EAGAIN || errno == EINTR)
			goto retry;

		goto out;
	}

	ret = io_getevents(info->ctx, 1, MAX_AIO_REQS, info->events, NULL);
	nr = ret;
	if (nr > 0) {
	rewrite:
		ret = write(info->done_fd[1], &nr, sizeof(nr));
		if (ret < 0) {
			eprintf("can't notify tgtd, %m\n");
		if (errno == EAGAIN || errno == EINTR)
			goto rewrite;

		goto out;
		}
	}
	goto retry;
out:
	return NULL;
}

static void bs_aio_handler(int fd, int events, void *data)
{
	struct bd_aio_info *info = data;
	int i, nr_events, ret;

	ret = read(info->done_fd[0], &nr_events, sizeof(nr_events));
	if (ret < 0) {
		eprintf("wrong wakeup\n");
		return;
	}

	/* FIXME: need to handle failure */
	for (i = 0; i < nr_events; i++) {
		struct io_event *ep = &info->events[i];
		target_cmd_io_done(ep->data, 0);
	}

	write(info->command_fd[1], &nr_events, sizeof(nr_events));
}

static int
bd_aio_open(struct tgt_device *dev, char *path, int *fd, uint64_t *size)
{
	int ret;
	struct bd_aio_info *info =
		(struct bd_aio_info *) ((char *)dev + sizeof(*dev));

	*fd = backed_file_open(path, O_RDWR| O_LARGEFILE, size);
	if (*fd < 0)
		return *fd;

	ret = io_queue_init(MAX_AIO_REQS, &info->ctx);
	if (ret) {
		eprintf("fail to create aio_queue, %m\n");
		goto close_dev_fd;
	}

	ret = pipe(info->command_fd);
	if (ret)
		goto close_ctx;

	ret = pipe(info->done_fd);
	if (ret)
		goto close_command_fd;

	ret = tgt_event_add(info->done_fd[0], EPOLLIN, bs_aio_handler, info);
	if (ret)
		goto close_done_fd;

	ret = pthread_create(&info->aio_thread, NULL, bs_aio_endio_thread,
			     info);
	if (ret)
		goto event_del;

	write(info->command_fd[1], &ret, sizeof(ret));

	return 0;
event_del:
	tgt_event_del(info->done_fd[0]);
close_done_fd:
	close(info->done_fd[0]);
	close(info->done_fd[1]);
close_command_fd:
	close(info->command_fd[0]);
	close(info->command_fd[1]);
close_ctx:
	io_destroy(info->ctx);
close_dev_fd:
	close(*fd);
	return -1;
}

static void bd_aio_close(struct tgt_device *dev)
{
	struct bd_aio_info *info;

	info = (struct bd_aio_info *) ((char *)dev + sizeof(*dev));

	pthread_cancel(info->aio_thread);
	pthread_join(info->aio_thread, NULL);
	io_destroy(info->ctx);
	close(dev->fd);
}

static int bd_aio_cmd_submit(struct tgt_device *dev, uint8_t *scb, int rw,
			     uint32_t datalen, unsigned long *uaddr,
			     uint64_t offset, int *async, void *key)
{
	struct bd_aio_info *info;
	struct iocb iocb, *io;
	int ret;

	info = (struct bd_aio_info *) ((char *)dev + sizeof(*dev));

	io = &iocb;
	memset(io, 0, sizeof(*io));

	dprintf("%d %d %u %lx %" PRIx64 " %p %p\n", dev->fd, rw, datalen,
		*uaddr, offset, io, key);

	if (rw == READ)
		io_prep_pread(io, dev->fd, (void *) *uaddr, datalen, offset);
	else
		io_prep_pwrite(io, dev->fd, (void *) *uaddr, datalen, offset);

	io->data = key;
	ret = io_submit(info->ctx, 1, &io);

	if (ret == 1) {
		*async = 1;
		return 0;
	} else
		return 1;
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
