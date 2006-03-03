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

#include <linux/fs.h>
#include <linux/netlink.h>
#include <scsi/scsi_tgt_if.h>

#include "tgtd.h"
#include "tgtadm.h"
#include "tgt_sysfs.h"

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

struct target {
	int tid;

	uint64_t max_device;
	struct tgt_device **devt;
	struct qelem device_list;

	/* TODO: move to device */
	struct qelem cqueue;
};

static struct target *tgtt[MAX_NR_TARGET];
static struct target *hostt[MAX_NR_HOST];

static struct target *target_get(int tid)
{
	if (tid >= MAX_NR_TARGET) {
		eprintf("Too larget target id %d\n", tid);
		return NULL;
	}
	return tgtt[tid];
}

static struct tgt_device *device_get(struct target *target, uint64_t dev_id)
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
	struct tgt_device *device;
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
	void *p;

	if (size != (size_t) size)
		return 0;
	p = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (p == MAP_FAILED)
		return 0;
	else
		return (unsigned long) p;
	return 0;
}

static void tgt_device_link(struct target *target, struct tgt_device *dev)
{
	struct tgt_device *ent;
	struct qelem *pos;

	list_for_each(pos, &target->device_list) {
		ent = list_entry(pos, struct tgt_device, dlist);
		if (dev->lun < ent->lun)
			break;
	}
	insque(&dev->dlist, pos);
}

int tgt_device_create(int tid, uint64_t dev_id, char *path)
{
	struct target *target;
	struct tgt_device *device;
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

	err = tgt_device_dir_create(tid, dev_id);
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
	device->lun = dev_id;
	snprintf(device->scsi_id, sizeof(device->scsi_id),
		 "deadbeaf%d:%" PRIu64, tid, dev_id);
	target->devt[dev_id] = device;

	if (device->addr)
		eprintf("Succeed to mmap the device %" PRIx64 "\n",
			device->addr);

	tgt_device_link(target, device);

	eprintf("Succeed to add a logical unit %" PRIu64 " to the target %d\n",
		dev_id, tid);

	return 0;
close_dev_fd:
	close(dev_fd);
	return err;
}

int tgt_device_destroy(int tid, uint64_t dev_id)
{
	struct target *target;
	struct tgt_device *device;

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

	close(device->fd);

	tgt_device_dir_delete(tid, dev_id);

	remque(&device->dlist);

	free(device);
	return 0;
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
	struct tgt_device *device;
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

	result = scsi_cmd_process(host_no, ev_req->k.cmd_req.scb,
				  &len, ev_req->k.cmd_req.data_len,
				  &uaddr, &rw, &try_map, &offset,
				  ev_req->k.cmd_req.lun, device,
				  &target->device_list);

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

static int scsi_cmd_done(int do_munmap, int do_free, uint64_t uaddr, int len)
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

static void cmd_done(struct tgt_event *ev)
{
	struct target *target;
	struct tgt_device *device;
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

void nl_event_handle(int nl_fd)
{
	struct nlmsghdr *nlh;
	struct tgt_event *ev;
	char buf[NLMSG_SPACE(sizeof(struct tgt_event))];
	int err;

	err = __nl_read(nl_fd, buf, sizeof(buf), MSG_WAITALL);

	nlh = (struct nlmsghdr *) buf;
	ev = (struct tgt_event *) NLMSG_DATA(nlh);

	if (nlh->nlmsg_len != err) {
		eprintf("unexpected len %d %d %d %d\n",
			nlh->nlmsg_len, sizeof(*ev), sizeof(buf), err);
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
	int err;

	if (!tgtt[tid]) {
		eprintf("target is not found %d\n", tid);
		return -EINVAL;
	}

	if (hostt[host_no]) {
		eprintf("host is already binded %d %d\n", tid, host_no);
		return -EINVAL;
	}

	err = tgt_target_dir_attr_create(tid, "hostno", "%d\n", host_no);
	if (err < 0)
		return -EINVAL;

	eprintf("Succeed to bind the target %d to the scsi host %d\n",
		tid, host_no);
	hostt[host_no] = tgtt[tid];
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

	target->devt = calloc(DEFAULT_NR_DEVICE, sizeof(struct tgt_device *));
	if (!target->devt) {
		eprintf("Out of memoryn\n");
		err = 0;
		goto free_target;
	}
	target->max_device = DEFAULT_NR_DEVICE;

	err = tgt_target_dir_create(tid);
	if (err < 0)
		goto free_device_table;

	INIT_LIST_HEAD(&target->device_list);

	eprintf("Succeed to create a new target %d\n", tid);
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
	return 0;
}
