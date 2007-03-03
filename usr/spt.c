/*
 * SCSI pass through
 *
 * Copyright (C) 2006-2007 FUJITA Tomonori <tomof@acm.org>
 * Copyright (C) 2006-2007 Mike Christie <michaelc@cs.wisc.edu>
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
#include <sys/epoll.h>
#include <limits.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <linux/types.h>
#include <scsi/sg.h>
#include <linux/bsg.h>

#include "list.h"
#include "util.h"
#include "tgtd.h"
#include "target.h"
#include "scsi.h"
#include "spc.h"

static void sg_handler(int fd, int events, void *data)
{
	int i, err;
	struct sg_io_v4 hdrs[64];
	struct tgt_device *dev = data;

	err = read(dev->fd, hdrs, sizeof(hdrs));
	if (err < 0)
		return;

	for (i = 0; i < err / sizeof(hdrs[0]); i++) {
		struct scsi_cmd *cmd = (void *) (unsigned long) hdrs[i].usr_ptr;
		if (hdrs[i].din_resid)
			cmd->len = hdrs[i].din_resid;
		target_cmd_io_done(cmd, 0);
	}
}

static int bd_sg_open(struct tgt_device *dev,
		      char *path, int *fd, uint64_t *size)
{
	int err, maj, min;
	char *sd, buf[256];
	struct stat64 st;
	struct timeval t;
	struct sg_io_v4 hdr, *h;
	int nr_queue_cmd;

	/* we assume something like /dev/sda */
	eprintf("%Zd %Zd %Zd\n", sizeof(hdr), sizeof(*h), sizeof(struct sg_io_v4));

	*fd = backed_file_open(path, 0, size);
	if (*fd < 0)
		return *fd;

	err = fstat64(*fd, &st);
	if (err < 0) {
		eprintf("can't get stat %d, %m\n", *fd);
		goto close_fd;
	}

	if(!S_ISBLK(st.st_mode)) {
		eprintf("only scsi devices are supported %s\n", path);
		err = -EINVAL;
		goto close_fd;
	}

	close(*fd);

	sd = strrchr(path, '/');
	if (!sd) {
		eprintf("invalid path %s\n", path);
		return -EINVAL;
	}

	snprintf(buf, sizeof(buf), "/sys/class/bsg%s/dev", sd);
	*fd = open(buf, O_RDONLY);
	if (*fd < 0) {
		eprintf("can't open %s, %m\n", buf);
		return -errno;
	}

	err = read(*fd, buf, sizeof(buf));
	if (err < 0) {
		eprintf("can't open %s, %m\n", buf);
		goto close_fd;
	}

	err = sscanf(buf, "%u:%u", &maj, &min);
	if (err < 0) {
		eprintf("can't get bsg major/minor number %s, %m\n", buf);
		goto close_fd;
	}

	dprintf("%s's bsg device number: %d %d\n", path, maj, min);
	close(*fd);

	err = gettimeofday(&t, NULL);
	if (err) {
		eprintf("can't get temporary name for bsg device, %m\n");
		return -errno;
	}

	memset(buf, 0, sizeof(buf));
	snprintf(buf, sizeof(buf), "/tmp/%lx%lx", t.tv_sec, t.tv_usec);
	err = mknod(buf, S_IFCHR | S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH,
		    maj << 8 | min);
	if (err < 0) {
		eprintf("can't create the bsg device %s, %m\n", buf);
		return -errno;
	}

	*fd = open(buf, O_RDWR | O_NONBLOCK);

	dprintf("%d %s\n", *fd, buf);
	unlink(buf);

	if (*fd < 0) {
		eprintf("can't open the bsg device %s, %m\n", buf);
		return -errno;
	}

	/* workaround */
	nr_queue_cmd = 128;
	err = ioctl(*fd, SG_SET_COMMAND_Q, &nr_queue_cmd);
	if (err) {
		eprintf("can't set the queue depth %d, %m\n", nr_queue_cmd);
		goto close_fd;
	}

	err = tgt_event_add(*fd, EPOLLIN, sg_handler, dev);
	if (err) {
		free(dev);
		goto close_fd;
	}

	return 0;
close_fd:
	close(*fd);
	return err;
}

static void bd_sg_close(struct tgt_device *dev)
{
	tgt_event_del(dev->fd);
	close(dev->fd);
}

static int bd_sg_cmd_done(int do_munmap, int do_free, uint64_t uaddr, int len)
{
	return 0;
}

static int sg_cmd_submit(struct scsi_cmd *cmd)
{
	int ret;
	struct sg_io_v4 hdr;

	/* TODO sense */

	dprintf("%x %d %u %" PRIx64"\n", cmd->scb[0], cmd->rw, cmd->len, cmd->uaddr);
	memset(&hdr, 0, sizeof(hdr));
	hdr.guard = 'Q';
	hdr.request_len = 16;
	hdr.request = (unsigned long) cmd->scb;

	if (cmd->rw) {
		hdr.dout_xfer_len = cmd->len;
		hdr.dout_xferp = cmd->uaddr;
	} else {
		hdr.din_xfer_len = cmd->len;
		hdr.din_xferp = cmd->uaddr;
	}

	hdr.max_response_len = sizeof(cmd->sense_buffer);
	hdr.response = (unsigned long) cmd->sense_buffer;

	hdr.usr_ptr = (unsigned long) cmd;

	ret = write(cmd->dev->fd, &hdr, sizeof(hdr));
	if (ret == sizeof(hdr)) {
		cmd->async = 1;
		return 0;
	} else {
		eprintf("%d %m\n", ret);
		return -1;
	}
}

struct backedio_template sg_bdt = {
	.bd_open		= bd_sg_open,
	.bd_close		= bd_sg_close,
	.bd_cmd_done		= bd_sg_cmd_done,
};

static int spt_cmd_perform(int host_no, struct scsi_cmd *cmd)
{
	int ret;
	ret = sg_cmd_submit(cmd);
	if (ret) {
		cmd->len = 0;
		sense_data_build(cmd, ILLEGAL_REQUEST, 0x25, 0);
		return SAM_STAT_CHECK_CONDITION;
	} else
		return SAM_STAT_GOOD;
}

struct device_command_operations spt_ops[] = {
	[0x40 ... 0x7f] = {spt_cmd_perform,},

	{spc_report_luns,},
	{spt_cmd_perform,},
	{spt_cmd_perform,},
	{spt_cmd_perform,},
	{spt_cmd_perform,},
	{spt_cmd_perform,},
	{spt_cmd_perform,},
	{spt_cmd_perform,},

	{spt_cmd_perform,},
	{spt_cmd_perform,},
	{spt_cmd_perform,},
	{spt_cmd_perform,},
	{spt_cmd_perform,},
	{spt_cmd_perform,},
	{spt_cmd_perform,},
	{spt_cmd_perform,},

	[0xb0 ... 0xff] = {spt_cmd_perform},
};
