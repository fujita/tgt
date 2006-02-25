/*
 * SCSI target daemon core functions
 *
 * Copyright (C) 2005 FUJITA Tomonori <tomof@acm.org>
 * Copyright (C) 2005 Mike Christie <michaelc@cs.wisc.edu>
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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <search.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <linux/fs.h>
#include <linux/netlink.h>
#include <scsi/scsi_tgt_if.h>

#include "tgtd.h"
#include "tgtadm.h"
#include "dl.h"
#include "tgt_sysfs.h"
#include "util.h"

#define	MAX_NR_TARGET		1024
#define	MAX_NR_HOST		1024
#define	DEFAULT_NR_DEVICE	64
#define	MAX_NR_DEVICE		(1 << 20)

struct cmd {
	struct qelem clist;
	uint32_t cid;
	uint64_t dev_id;
	uint64_t uaddr;
	uint32_t len;
	int mmap;
};

struct device {
	int fd;
	uint64_t addr; /* persistent mapped address */
	uint64_t size;
	int state;

	/* queue */
};

struct target {
	int tid;
	struct device **devt;
	uint64_t max_device;

	/* TODO: move to device */
	struct qelem cqueue;
};

static struct target *tgtt[MAX_NR_TARGET];
static struct target *hostt[MAX_NR_HOST];

static mode_t dmode = S_IRUSR|S_IWUSR|S_IXUSR|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH;
static mode_t fmode = S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH;

static struct target *target_get(int tid)
{
	if (tid >= MAX_NR_TARGET) {
		eprintf("Too larget target id %d\n", tid);
		return NULL;
	}
	return tgtt[tid];
}

static struct device *device_get(struct target *target, uint64_t dev_id)
{
	if (dev_id < target->max_device || dev_id < MAX_NR_DEVICE)
		return target->devt[dev_id];

	dprintf("Invalid device id %" PRIu64 "%d\n", dev_id, MAX_NR_DEVICE);
	return NULL;
}

static struct target *host_to_target(int host_no)
{
	if (host_no < MAX_NR_HOST)
		return hostt[host_no];

	return NULL;
}

static void resize_device_table(struct target *target, uint64_t did)
{
	struct device *device;
	void *p, *q;

	p = calloc(did + 1, sizeof(device));
	memcpy(p, target->devt, sizeof(device) * target->max_device);
	q = target->devt;
	target->devt = p;
	target->max_device = did + 1;
	free(q);
}

static uint64_t try_mmap_device(int fd, uint64_t size)
{
/* 	void *p; */

/* 	p = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0); */
/* 	if (p == MAP_FAILED) */
/* 		return 0; */
/* 	else */
/* 		return (unsigned long) p; */
	return 0;
}

static int device_dir_create(int tid, uint64_t dev_id, int dev_fd, uint64_t size)
{
	char path[PATH_MAX], buf[64];
	int fd, err;

	snprintf(path, sizeof(path), TGT_DEVICE_SYSFSDIR
		 "/device%d:%" PRIu64, tid, dev_id);

	err = mkdir(path, dmode);
	if (err < 0) {
		eprintf("Cannot create %s\n", path);
		return err;
	}

	snprintf(path, sizeof(path), TGT_DEVICE_SYSFSDIR
		 "/device%d:%" PRIu64 "/fd", tid, dev_id);
	fd = open(path, O_RDWR|O_CREAT|O_EXCL, fmode);
	if (fd < 0) {
		eprintf("Cannot create %s\n", path);
		return err;
	}
	snprintf(buf, sizeof(buf), "%d", dev_fd);
	err = write(fd, buf, strlen(buf));
	close(fd);
	if (err < 0) {
		eprintf("Cannot write %s\n", path);
		return err;
	}

	snprintf(path, sizeof(path), TGT_DEVICE_SYSFSDIR
		 "/device%d:%" PRIu64 "/size", tid, dev_id);
	fd = open(path, O_RDWR|O_CREAT|O_EXCL, fmode);
	if (fd < 0) {
		eprintf("Cannot create %s\n", path);
		return err;
	}
	snprintf(buf, sizeof(buf), "%" PRIu64, size);
	err = write(fd, buf, strlen(buf));
	close(fd);
	if (err < 0) {
		eprintf("Cannot write %s\n", path);
		return err;
	}

	return 0;
}

#ifndef O_LARGEFILE
#define O_LARGEFILE	0100000
#endif

int tgt_device_create(int tid, uint64_t dev_id, char *path)
{
	struct target *target;
	struct device *device;
	int err, dev_fd;
	uint64_t size;

	dprintf("%d %" PRIu64 " %s\n", tid, dev_id, path);

	target = target_get(tid);
	if (!target)
		return -ENOENT;

	device = device_get(target, dev_id);
	if (device) {
		eprintf("device %" PRIu64 " already exists\n", dev_id);
		return -EINVAL;
	}

	dev_fd = open(path, O_RDWR | O_LARGEFILE);
	if (dev_fd < 0) {
		eprintf("Could not open %s errno %d\n", path, errno);
		return dev_fd;
	}

	err = ioctl(dev_fd, BLKGETSIZE64, &size);
	if (err < 0) {
		eprintf("Cannot get size %d\n", dev_fd);
		return err;
	}

	err = device_dir_create(tid, dev_id, dev_fd, size);
	if (err < 0)
		goto close_dev_fd;

	if (dev_id >= target->max_device)
		resize_device_table(target, dev_id);

	device = malloc(sizeof(*device));
	if (!device)
		goto close_dev_fd;

	device->fd = dev_fd;
	device->state = 0;
	device->addr = try_mmap_device(dev_fd, size);
	device->size = size;
	target->devt[dev_id] = device;

	if (device->addr)
		eprintf("Succeed to mmap the device %" PRIx64 "\n",
			device->addr);

	return 0;
close_dev_fd:
	close(dev_fd);
	return err;
}

static void device_dir_remove(int tid, uint64_t dev_id)
{
	int err;
	char path[PATH_MAX];

	snprintf(path, sizeof(path), TGT_DEVICE_SYSFSDIR
		 "/device%d:%" PRIu64 "/fd", tid, dev_id);
	err = unlink(path);
	if (err < 0)
		eprintf("Cannot unlink %s\n", path);

	snprintf(path, sizeof(path), TGT_DEVICE_SYSFSDIR
		 "/device%d:%" PRIu64 "/size", tid, dev_id);
	err = unlink(path);
	if (err < 0)
		eprintf("Cannot unlink %s\n", path);

	snprintf(path, sizeof(path), TGT_DEVICE_SYSFSDIR
		 "/device%d:%" PRIu64, tid, dev_id);
	err = rmdir(path);
	if (err < 0)
		eprintf("Cannot unlink %s\n", path);
}

int tgt_device_destroy(int tid, uint64_t dev_id)
{
	struct target *target;
	struct device *device;
	char path[PATH_MAX], buf[64];
	int dev_fd, fd, err;

	/* TODO: check whether the device has flying commands. */

	dprintf("%u %" PRIu64 "\n", tid, dev_id);

	target = target_get(tid);
	if (!target)
		return -ENOENT;

	device = device_get(target, dev_id);
	if (!device) {
		eprintf("device %" PRIu64 " not found\n", dev_id);
		return -EINVAL;
	}

	target->devt[dev_id] = NULL;
	if (device->addr)
		munmap((void *) (unsigned long) device->addr, device->size);

	snprintf(path, sizeof(path), TGT_DEVICE_SYSFSDIR
		 "/device%d:%" PRIu64 "/fd", tid, dev_id);
	fd = open(path, O_RDONLY);
	if (fd < 0)
		eprintf("%s %d\n", path, errno);

	err = read(fd, buf, sizeof(buf));
	close(fd);
	if (err < 0)
		eprintf("%d\n", err);

	sscanf(buf, "%d\n", &dev_fd);
	close(dev_fd);

	device_dir_remove(tid, dev_id);

	free(device);
	return err;
}

int tgt_device_init(void)
{
	int err;

	system("rm -rf " TGT_TARGET_SYSFSDIR);
	system("rm -rf " TGT_DEVICE_SYSFSDIR);

	err = mkdir(TGT_TARGET_SYSFSDIR, dmode);
	if (err < 0) {
		perror("Cannot create " TGT_TARGET_SYSFSDIR);
		return err;
	}

	err = mkdir(TGT_DEVICE_SYSFSDIR, dmode);
	if (err < 0)
		perror("Cannot create " TGT_DEVICE_SYSFSDIR);

	return err;
}

static struct cmd *find_cmd(struct target *target, uint32_t cid)
{
	struct cmd *cmd;
	list_for_each_entry(cmd, &target->cqueue, clist) {
		if (cmd->cid == cid)
			return cmd;
	}
	return NULL;
}

/* TODO: coalesce responses */
static int cmd_queue(struct tgt_event *ev_req, int nl_fd)
{
	struct target *target;
	struct device *device;
	int result, len = 0;
	char resbuf[NLMSG_SPACE(sizeof(struct tgt_event))];
	struct tgt_event *ev_res = NLMSG_DATA(resbuf);
	uint64_t offset, dev_id;
	uint32_t cid = ev_req->k.cmd_req.cid;
	uint8_t rw = 0, try_map = 0;
	unsigned long uaddr = 0;
	int host_no = ev_req->k.cmd_req.host_no;
	struct cmd *cmd;

	target = host_to_target(host_no);
	if (!target) {
		eprintf("%d is not bind to any target\n", host_no);
		return 0;
	}

	dev_id = scsi_get_devid(ev_req->k.cmd_req.lun);
	dprintf("%u %x %" PRIx64 "\n", cid, ev_req->k.cmd_req.scb[0], dev_id);

	device = device_get(target, dev_id);
	if (device)
		uaddr = target->devt[dev_id]->addr;

	result = scsi_cmd_process(host_no, target->tid, ev_req->k.cmd_req.scb,
				  &len, ev_req->k.cmd_req.data_len,
				  &uaddr, &rw, &try_map, &offset,
				  ev_req->k.cmd_req.lun);

	dprintf("%u %x %lx %" PRIu64 " %d\n",
		cid, ev_req->k.cmd_req.scb[0], uaddr, offset, result);

	/* TODO: preallocate cmd */
	cmd = malloc(sizeof(*cmd));
 	cmd->cid = cid;
	cmd->dev_id = dev_id;
	cmd->uaddr = uaddr;
	cmd->len = len;
	cmd->mmap = try_map;

	insque(&cmd->clist, &target->cqueue);

	ev_res->u.cmd_rsp.host_no = host_no;
	ev_res->u.cmd_rsp.cid = cid;
	ev_res->u.cmd_rsp.len = len;
	ev_res->u.cmd_rsp.result = result;
	ev_res->u.cmd_rsp.uaddr = uaddr;
	ev_res->u.cmd_rsp.rw = rw;

	return __nl_write(nl_fd, TGT_UEVENT_CMD_RSP, resbuf,
			  NLMSG_SPACE(sizeof(*ev_res)));
}

static void cmd_done(struct tgt_event *ev)
{
	struct target *target;
	struct device *device;
	struct cmd *cmd;
	int err, do_munmap, host_no = ev->k.cmd_done.host_no;
	uint32_t cid = ev->k.cmd_done.cid;

	target = host_to_target(host_no);
	if (!target) {
		eprintf("%d is not bind to any target\n", host_no);
		return;
	}

	cmd = find_cmd(target, cid);
	if (!cmd) {
		eprintf("Cannot find cmd %d %u\n", host_no, cid);
		return;
	}
	remque(&cmd->clist);
	do_munmap = cmd->mmap;

	if (do_munmap) {
		device = device_get(target, cmd->dev_id);
		if (!device) {
			eprintf("%" PRIu64 " is null\n", cmd->dev_id);
			exit(1);
		}

		if (device->addr)
			do_munmap = 0;
	}
	err = scsi_cmd_done(do_munmap, !cmd->mmap, cmd->uaddr, cmd->len);

	dprintf("%d %" PRIx64 " %u %d\n", cmd->mmap, cmd->uaddr, cmd->len, err);

	free(cmd);
}

static int set_pdu_size(int fd)
{
	struct nlmsghdr *nlh;
	char buf[1024];
	int err;

peek_again:
	err = __nl_read(fd, buf, sizeof(buf), MSG_PEEK);
	if (err < 0) {
		if (errno == EAGAIN || errno == EINTR)
			goto peek_again;
		return err;
	}

	nlh = (struct nlmsghdr *) buf;

	dprintf("%d\n", nlh->nlmsg_len);

	return nlh->nlmsg_len;
}

void nl_event_handle(int nl_fd)
{
	struct nlmsghdr *nlh;
	struct tgt_event *ev;
	static int pdu_size;
	char buf[1024];
	int err;

	if (!pdu_size)
		pdu_size = set_pdu_size(nl_fd);

	err = __nl_read(nl_fd, buf, pdu_size, MSG_WAITALL);

	nlh = (struct nlmsghdr *) buf;
	ev = (struct tgt_event *) NLMSG_DATA(nlh);

	if (nlh->nlmsg_len != pdu_size) {
		eprintf("unexpected len %d %d\n", nlh->nlmsg_len, pdu_size);
		exit(1);
	}

	switch (nlh->nlmsg_type) {
	case TGT_KEVENT_CMD_REQ:
		cmd_queue(ev, nl_fd);
		break;
	case TGT_KEVENT_CMD_DONE:
		cmd_done(ev);
		break;
	default:
		eprintf("unknown event %u\n", nlh->nlmsg_type);
		exit(1);
	}
}

int tgt_target_bind(int tid, int host_no)
{
	if (!tgtt[tid]) {
		eprintf("target is not found %d\n", tid);
		return -EINVAL;
	}

	if (hostt[host_no]) {
		eprintf("host is already binded %d %d\n", tid, host_no);
		return -EINVAL;
	}

	hostt[host_no] = tgtt[tid];
	return 0;
}

static int target_dir_create(int tid)
{
	char path[PATH_MAX];
	int err;

	snprintf(path, sizeof(path), TGT_TARGET_SYSFSDIR "/target%d", tid);
	err = mkdir(path, dmode);
	if (err < 0) {
		eprintf("Cannot create %s %d\n", path, errno);
		return err;
	}
	return 0;
}

int tgt_target_create(int tid)
{
	int err;
	struct target *target;

	if (tid >= MAX_NR_TARGET) {
		eprintf("Too larget target id %d\n", tid);
		return -EINVAL;
	}

	if (tgtt[tid]) {
		eprintf("Target id %d already exists\n", tid);
		return -EINVAL;
	}

	target = malloc(sizeof(*target));
	if (!target) {
		eprintf("Out of memoryn\n");
		return -ENOMEM;
	}

	target->tid = tid;
	INIT_LIST_HEAD(&target->cqueue);

	target->devt = calloc(DEFAULT_NR_DEVICE, sizeof(struct device *));
	if (!target->devt) {
		eprintf("Out of memoryn\n");
		err = 0;
		goto free_target;
	}
	target->max_device = DEFAULT_NR_DEVICE;

	err = target_dir_create(tid);
	if (err < 0)
		goto free_device_table;

	tgtt[tid] = target;
	return 0;

free_device_table:
	free(target->devt);
free_target:
	free(target);
	return err;
}

int tgt_target_destroy(int tid)
{
	/* TODO */
	return 0;
}
