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
#include <pthread.h>

#include <linux/fs.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "list.h"
#include "util.h"
#include "tgtd.h"
#include "scsi.h"

#include "bs_aio.h"

#ifndef O_DIRECT
#define O_DIRECT 040000
#endif

/* FIXME */
#define MAX_AIO_REQS 2048

struct bs_aio_info {
	int afd;
	io_context_t ctx;

	struct io_event events[MAX_AIO_REQS];
};

static void bs_aio_endio(int fd, int events, void *data)
{
	struct bs_aio_info *info = data;
	int i, ret;
	uint64_t total, nr;

retry:
	ret = read(info->afd, &total, sizeof(total));
	if (ret < 0) {
		eprintf("AIO pthread will be dead, %m\n");
		if (errno == EAGAIN || errno == EINTR)
			goto retry;

		return;
	}
get_events:
	nr = min_t(long, total, MAX_AIO_REQS);
	ret = io_getevents(info->ctx, 1, nr, info->events, NULL);
	if (ret <= 0)
		return;

	nr = ret;
	total -= nr;

	for (i = 0; i < nr; i++) {
		struct io_event *ep = &info->events[i];
		struct scsi_cmd *cmd = (void *)(unsigned long)ep->data;
		int result;
		uint32_t length;

		switch (cmd->scb[0]) {
		case WRITE_6:
		case WRITE_10:
		case WRITE_12:
		case WRITE_16:
			length = scsi_get_out_length(cmd);
			break;
		default:
			length = scsi_get_in_length(cmd);
			break;
		}

		if (ep->res == length)
			result = SAM_STAT_GOOD;
		else {
			sense_data_build(cmd, MEDIUM_ERROR, 0);
			result = SAM_STAT_CHECK_CONDITION;
		}

		target_cmd_io_done(cmd, result);
	}

	if (total)
		goto get_events;
}

static int bs_aio_open(struct scsi_lu *lu, char *path, int *fd, uint64_t *size)
{
	*fd = backed_file_open(path, O_RDWR|O_LARGEFILE|O_DIRECT, size);
	if (*fd < 0)
		return *fd;
	return 0;
}

static int bs_aio_init(struct scsi_lu *lu)
{
	int ret, afd;
	struct bs_aio_info *info =
		(struct bs_aio_info *) ((char *)lu + sizeof(*lu));

	ret = io_setup(MAX_AIO_REQS, &info->ctx);
	if (ret) {
		eprintf("fail to create aio_queue, %m\n");
		return -1;
	}

	afd = eventfd(0);
	if (afd < 0) {
		eprintf("fail to create eventfd, %m\n");
		goto close_ctx;
	}

	ret = fcntl(afd, F_SETFL, fcntl(afd, F_GETFL, 0) | O_NONBLOCK);
	if (ret) {
		eprintf("fail to configure eventfd, %m\n");
		goto close_eventfd;
	}

	ret = tgt_event_add(afd, EPOLLIN, bs_aio_endio, info);
	if (ret)
		goto close_eventfd;

	info->afd = afd;

	return 0;

close_eventfd:
	close(afd);
close_ctx:
	io_destroy(info->ctx);
	return -1;
}

static void bs_aio_close(struct scsi_lu *lu)
{
	close(lu->fd);
}

static void bs_aio_exit(struct scsi_lu *lu)
{
	struct bs_aio_info *info =
		(struct bs_aio_info *) ((char *)lu + sizeof(*lu));

	close(info->afd);
	io_destroy(info->ctx);
}

static int bs_aio_cmd_submit(struct scsi_cmd *cmd)
{
	struct scsi_lu *lu = cmd->dev;
	struct bs_aio_info *info =
		(struct bs_aio_info *)((char *)lu + sizeof(*lu));
	struct iocb iocb, *io;
	uint32_t length;
	int ret = 0, do_io = 0;

	io = &iocb;
	memset(io, 0, sizeof(*io));

	switch (cmd->scb[0]) {
	case SYNCHRONIZE_CACHE:
	case SYNCHRONIZE_CACHE_16:
		break;
	case WRITE_6:
	case WRITE_10:
	case WRITE_12:
	case WRITE_16:
		do_io = 1;
		length = scsi_get_out_length(cmd);
		io_prep_pwrite(io, lu->fd, scsi_get_out_buffer(cmd),
			       length, cmd->offset, info->afd);

		break;
	case READ_6:
	case READ_10:
	case READ_12:
	case READ_16:
		do_io = 1;
		length = scsi_get_in_length(cmd);
		io_prep_pread(io, lu->fd, scsi_get_in_buffer(cmd),
			      length, cmd->offset, info->afd);
		break;
	default:
		break;
	}

	if (do_io) {
		io->aio_data = (uint64_t)(unsigned long)cmd;
		ret = io_submit(info->ctx, 1, &io);
		if (ret == 1) {
			set_cmd_async(cmd);
			ret = 0;
		} else {
			sense_data_build(cmd, MEDIUM_ERROR, 0);
			ret = SAM_STAT_CHECK_CONDITION;
		}
	}

	return ret;
}

static int bs_aio_cmd_done(struct scsi_cmd *cmd)
{
	return 0;
}

static struct backingstore_template aio_bst = {
	.bs_name		= "aio",
	.bs_datasize		= sizeof(struct bs_aio_info),
	.bs_init		= bs_aio_init,
	.bs_exit		= bs_aio_exit,
	.bs_open		= bs_aio_open,
	.bs_close		= bs_aio_close,
	.bs_cmd_submit		= bs_aio_cmd_submit,
	.bs_cmd_done		= bs_aio_cmd_done,
};

__attribute__((constructor)) static void bs_rdwr_constructor(void)
{
	register_backingstore_template(&aio_bst);
}
