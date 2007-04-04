/*
 * AIO file backing store routine
 *
 * Copyright (C) 2006-2007 FUJITA Tomonori <tomof@acm.org>
 * Copyright (C) 2006-2007 Mike Christie <michaelc@cs.wisc.edu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
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

struct bs_aio_info {
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
	struct bs_aio_info *info = arg;
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
	dprintf("%d", ret);
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
	struct bs_aio_info *info = data;
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
bs_aio_open(struct scsi_lu *lu, char *path, int *fd, uint64_t *size)
{
	int ret;
	struct bs_aio_info *info =
		(struct bs_aio_info *) ((char *)lu + sizeof(*lu));

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

static void bs_aio_close(struct scsi_lu *lu)
{
	struct bs_aio_info *info;

	info = (struct bs_aio_info *) ((char *)lu + sizeof(*lu));

	pthread_cancel(info->aio_thread);
	pthread_join(info->aio_thread, NULL);
	io_destroy(info->ctx);
	close(lu->fd);
}

static int bs_aio_cmd_submit(struct scsi_cmd *cmd)
{
	struct scsi_lu *lu = cmd->dev;
	struct bs_aio_info *info = (struct bs_aio_info *)((char *)lu + sizeof(*lu));
	struct iocb iocb, *io;
	int ret;

	io = &iocb;
	memset(io, 0, sizeof(*io));

	dprintf("%d %d %u %"  PRIx64 " %" PRIx64 " %p\n", lu->fd, cmd->rw, cmd->len,
		cmd->uaddr, cmd->offset, cmd);

	if (cmd->rw == READ)
		io_prep_pread(io, lu->fd, (void *)(unsigned long)cmd->uaddr,
			      cmd->len,	cmd->offset);
	else
		io_prep_pwrite(io, lu->fd, (void *)(unsigned long)cmd->uaddr,
			       cmd->len, cmd->offset);

	io->data = cmd;
	ret = io_submit(info->ctx, 1, &io);

	if (ret == 1) {
		cmd->async = 1;
		return 0;
	} else {
		dprintf("%d %d %u %"  PRIx64 " %" PRIx64 " %p\n", lu->fd, cmd->rw, cmd->len,
			cmd->uaddr, cmd->offset, cmd);
		return 1;
	}
}

static int bs_aio_cmd_done(int do_munmap, int do_free, uint64_t uaddr, int len)
{
	return 0;
}

struct backingstore_template aio_bst = {
	.bs_datasize		= sizeof(struct bs_aio_info),
	.bs_open		= bs_aio_open,
	.bs_close		= bs_aio_close,
	.bs_cmd_submit		= bs_aio_cmd_submit,
	.bs_cmd_done		= bs_aio_cmd_done,
};
