/*
 * rawio routine
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
#include <scsi/sg.h>
#include <sys/epoll.h>
#include <limits.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include "list.h"
#include "util.h"
#include "tgtd.h"
#include "target.h"

/*
 * this uses sg4, so you need to Jens' bsg tree now.
 */

static void sg_handler(int fd, int events, void *data)
{
	int i, err;
	struct sg_io_hdr hdrs[64];
	struct tgt_device *dev = data;

	err = read(dev->fd, hdrs, sizeof(hdrs));
	if (err < 0)
		return;

	for (i = 0; i < err / sizeof(hdrs[0]); i++) {
		struct cmd *cmd = (void *) hdrs[i].usr_ptr;
		dprintf("%d %p %u %u %x\n", i, hdrs[i].usr_ptr,
			hdrs[i].status, hdrs[i].resid,
			hdrs[i].info);
		if (hdrs[i].resid)
			cmd->len = hdrs[i].resid;
		target_cmd_io_done(hdrs[i].usr_ptr, 0);
	}
}

static int bd_sg_open(struct tgt_device *dev,
		      char *path, int *fd, uint64_t *size)
{
	int err, maj, min;
	char *sd, *bsgdev, buf[128];
	struct stat64 st;

	/* we assume something like /dev/sda */

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

	bsgdev = tempnam("/tmp", NULL);
	if (!bsgdev) {
		eprintf("can't get temporary name for bsg device, %m\n");
		return -errno;
	}

	err = mknod(bsgdev, S_IFCHR | S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH,
		    maj << 8 | min);
	if (err < 0) {
		eprintf("can't create the bsg device %s, %m\n", bsgdev);
		return -errno;
	}

	*fd = open(bsgdev, O_RDWR | O_NONBLOCK);

	dprintf("%d %s\n", *fd, bsgdev);
	unlink(bsgdev);
	free(bsgdev);

	if (*fd < 0) {
		eprintf("can't open the bsg device %s, %m\n", bsgdev);
		return -errno;
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

static int bd_sg_cmd_submit(struct tgt_device *dev, uint8_t *scb,
			    int rw, uint32_t datalen, unsigned long *uaddr,
			    uint64_t offset, int *async, void *key)
{
	int err;
	struct sg_io_hdr hdr;

	/* TODO sense */

	dprintf("%x %d %u %lx\n", scb[0], rw, datalen, *uaddr);
	memset(&hdr, 0, sizeof(hdr));
	hdr.interface_id = 'S';
	hdr.cmd_len = 16;
	hdr.cmdp = scb;
	hdr.dxfer_direction = rw ? SG_DXFER_TO_DEV : SG_DXFER_FROM_DEV;
	hdr.dxfer_len = datalen;
	hdr.dxferp = (void *) *uaddr;
/* 	hdr.mx_sb_len = sizeof(sense); */
/* 	hdr.sbp = sense; */
	hdr.timeout = 30000;
	hdr.usr_ptr = key;

	*async = 1;

	err = write(dev->fd, &hdr, sizeof(hdr));
	if (err != sizeof(hdr))
		eprintf("%d %m\n", err);
	else
		err = 0;
	return err;
}

struct backedio_template sg_bdt = {
	.bd_open		= bd_sg_open,
	.bd_close		= bd_sg_close,
	.bd_cmd_submit		= bd_sg_cmd_submit,
	.bd_cmd_done		= bd_sg_cmd_done,
};
