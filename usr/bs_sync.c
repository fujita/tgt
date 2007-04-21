/*
 * Synchronous I/O file backing store routine
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
#define _XOPEN_SOURCE 500

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

#include "list.h"
#include "util.h"
#include "tgtd.h"
#include "scsi.h"

#define NR_WORKER_THREADS	4

struct bs_sync_info {
	pthread_t ack_thread;
	pthread_t worker_thread[NR_WORKER_THREADS];

	/* protected by pipe */
	struct list_head ack_list;

	pthread_cond_t finished_cond;
	pthread_mutex_t finished_lock;
	struct list_head finished_list;

	/* wokers sleep on this and signaled by tgtd */
	pthread_cond_t pending_cond;
	/* locked by tgtd and workers */
	pthread_mutex_t pending_lock;
	/* protected by pending_lock */
	struct list_head pending_list;

	int command_fd[2];
	int done_fd[2];

	int stop;
};

static void *bs_sync_ack_fn(void *arg)
{
	struct bs_sync_info *info = arg;
	int command, ret, nr;
	struct scsi_cmd *cmd;

retry:
	ret = read(info->command_fd[0], &command, sizeof(command));
	if (ret < 0) {
		eprintf("ack pthread will be dead, %m\n");
		if (errno == EAGAIN || errno == EINTR)
			goto retry;

		goto out;
	}

	pthread_mutex_lock(&info->finished_lock);
retest:
	if (list_empty(&info->finished_list)) {
		pthread_cond_wait(&info->finished_cond, &info->finished_lock);
		goto retest;
	}

	while (!list_empty(&info->finished_list)) {
		cmd = list_entry(info->finished_list.next,
				 struct scsi_cmd, bs_list);

		dprintf("found %p\n", cmd);

		list_del(&cmd->bs_list);
		list_add(&cmd->bs_list, &info->ack_list);
	}

	pthread_mutex_unlock(&info->finished_lock);

	nr = 1;
rewrite:
	ret = write(info->done_fd[1], &nr, sizeof(nr));
	if (ret < 0) {
		eprintf("can't ack tgtd, %m\n");
		if (errno == EAGAIN || errno == EINTR)
			goto rewrite;

		goto out;
	}

	goto retry;
out:
	return NULL;
}

static void *bs_sync_worker_fn(void *arg)
{
	int ret, fd;
	void *buf;
	struct bs_sync_info *info = arg;
	struct scsi_cmd *cmd;

	while (1) {
		pthread_mutex_lock(&info->pending_lock);
	retest:
		if (list_empty(&info->pending_list)) {
			pthread_cond_wait(&info->pending_cond, &info->pending_lock);
			if (info->stop) {
				pthread_mutex_unlock(&info->pending_lock);
				break;
			}
			goto retest;
		}

		cmd = list_entry(info->pending_list.next,
				 struct scsi_cmd, bs_list);

		dprintf("got %p\n", cmd);

		list_del(&cmd->bs_list);
		pthread_mutex_unlock(&info->pending_lock);

		fd = cmd->dev->fd;
		buf = (void *)(unsigned long)cmd->uaddr;

		if (cmd->scb[0] == SYNCHRONIZE_CACHE ||
		    cmd->scb[0] == SYNCHRONIZE_CACHE_16)
			ret = fsync(fd);
		else if (cmd->rw == READ)
			ret = pread64(fd, buf, cmd->len, cmd->offset);
		else
			ret = pwrite64(fd, buf, cmd->len, cmd->offset);

		dprintf("io done %p %x %d %d\n", cmd, cmd->scb[0], ret, cmd->len);

		if (ret == cmd->len)
			cmd->result = SAM_STAT_GOOD;
		else {
			eprintf("io error %p %x %d %d %" PRIu64 ", %m\n",
				cmd, cmd->scb[0], ret, cmd->len, cmd->offset);
			cmd->result = SAM_STAT_CHECK_CONDITION;
			sense_data_build(cmd, MEDIUM_ERROR, 0x11, 0x0);
		}

		pthread_mutex_lock(&info->finished_lock);
		list_add(&cmd->bs_list, &info->finished_list);
		pthread_mutex_unlock(&info->finished_lock);

		pthread_cond_signal(&info->finished_cond);
	}

	return NULL;
}

static void bs_sync_handler(int fd, int events, void *data)
{
	struct bs_sync_info *info = data;
	struct scsi_cmd *cmd;
	int nr_events, ret;

	ret = read(info->done_fd[0], &nr_events, sizeof(nr_events));
	if (ret < 0) {
		eprintf("wrong wakeup\n");
		return;
	}

	while (!list_empty(&info->ack_list)) {
		cmd = list_entry(info->ack_list.next,
				 struct scsi_cmd, bs_list);

		dprintf("back to tgtd, %p\n", cmd);

		list_del(&cmd->bs_list);
		target_cmd_io_done(cmd, cmd->result);
	}

	write(info->command_fd[1], &nr_events, sizeof(nr_events));
}

static int
bs_sync_open(struct scsi_lu *lu, char *path, int *fd, uint64_t *size)
{
	int i, ret;
	struct bs_sync_info *info =
		(struct bs_sync_info *) ((char *)lu + sizeof(*lu));

	INIT_LIST_HEAD(&info->ack_list);
	INIT_LIST_HEAD(&info->finished_list);
	INIT_LIST_HEAD(&info->pending_list);

	*fd = backed_file_open(path, O_RDWR| O_LARGEFILE, size);
	if (*fd < 0)
		return *fd;

	pthread_cond_init(&info->finished_cond, NULL);
	pthread_cond_init(&info->pending_cond, NULL);

	pthread_mutex_init(&info->finished_lock, NULL);
	pthread_mutex_init(&info->pending_lock, NULL);

	ret = pipe(info->command_fd);
	if (ret)
		goto close_dev_fd;

	ret = pipe(info->done_fd);
	if (ret)
		goto close_command_fd;

	ret = tgt_event_add(info->done_fd[0], EPOLLIN, bs_sync_handler, info);
	if (ret)
		goto close_done_fd;

	ret = pthread_create(&info->ack_thread, NULL, bs_sync_ack_fn, info);
	if (ret)
		goto event_del;

	for (i = 0; i < ARRAY_SIZE(info->worker_thread); i++) {
		ret = pthread_create(&info->worker_thread[i], NULL,
				     bs_sync_worker_fn, info);
	}

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
close_dev_fd:
	close(*fd);

	pthread_cond_destroy(&info->finished_cond);
	pthread_cond_destroy(&info->pending_cond);
	pthread_mutex_destroy(&info->finished_lock);
	pthread_mutex_destroy(&info->pending_lock);

	return -1;
}

static void bs_sync_close(struct scsi_lu *lu)
{
	int i;
	struct bs_sync_info *info =
		(struct bs_sync_info *) ((char *)lu + sizeof(*lu));

	pthread_cancel(info->ack_thread);
	pthread_join(info->ack_thread, NULL);

	info->stop = 1;
	pthread_cond_broadcast(&info->pending_cond);

	for (i = 0; i < ARRAY_SIZE(info->worker_thread); i++)
		pthread_join(info->worker_thread[i], NULL);

	pthread_cond_destroy(&info->finished_cond);
	pthread_cond_destroy(&info->pending_cond);
	pthread_mutex_destroy(&info->finished_lock);
	pthread_mutex_destroy(&info->pending_lock);

	close(lu->fd);
}

static int bs_sync_cmd_submit(struct scsi_cmd *cmd)
{
	struct scsi_lu *lu = cmd->dev;
	struct bs_sync_info *info =
		(struct bs_sync_info *)((char *)lu + sizeof(*lu));

	dprintf("%d %d %u %"  PRIx64 " %" PRIx64 " %p\n", lu->fd, cmd->rw,
		cmd->len, cmd->uaddr, cmd->offset, cmd);

	pthread_mutex_lock(&info->pending_lock);

	list_add(&cmd->bs_list, &info->pending_list);

	pthread_mutex_unlock(&info->pending_lock);

	pthread_cond_signal(&info->pending_cond);

	cmd->async = 1;

	return 0;
}

static int bs_sync_cmd_done(struct scsi_cmd *cmd)
{
	return 0;
}

struct backingstore_template sync_bst = {
	.bs_datasize		= sizeof(struct bs_sync_info),
	.bs_open		= bs_sync_open,
	.bs_close		= bs_sync_close,
	.bs_cmd_submit		= bs_sync_cmd_submit,
	.bs_cmd_done		= bs_sync_cmd_done,
};
