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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>

#include <linux/fs.h>
#define BITS_PER_LONG (ULONG_MAX == 0xFFFFFFFFUL ? 32 : 64)
#include <linux/hash.h>
#include <linux/netlink.h>
#include <scsi/scsi.h>
#include <scsi/scsi_tgt_if.h>

#include "tgtd.h"
#include "tgtadm.h"
#include "tgt_sysfs.h"

/* better if we can include the followings in kernel header files. */
#define	MSG_SIMPLE_TAG	0x20
#define	MSG_HEAD_TAG	0x21
#define	MSG_ORDERED_TAG	0x22

#define	MAX_NR_TARGET		1024
#define	MAX_NR_HOST		1024
#define	DEFAULT_NR_DEVICE	64
#define	MAX_NR_DEVICE		(1 << 20)

#define	HASH_ORDER	4
#define	cmd_hashfn(cid)	hash_long((cid), HASH_ORDER)

enum {
	TGT_QUEUE_BLOCKED,
	TGT_QUEUE_DELETED,
};

enum {
	TGT_CMD_QUEUED,
	TGT_CMD_PROCESSED,
	TGT_CMD_MGMT,
};

struct cmd {
	struct list_head hlist;
	struct list_head qlist;
	struct list_head clist;
	uint32_t cid;
	uint64_t uaddr;
	uint32_t len;
	int mmapped;
	struct tgt_device *dev;
	unsigned long state;
	uint64_t mid;

	/* Kill the followings when we use shared memory instead of netlink. */
	int hostno;
	uint32_t data_len;
	uint8_t scb[16];
	uint8_t lun[8];
	int attribute;
	uint64_t tag;
};

struct target {
	int tid;
	int lid;

	uint64_t max_device;
	struct tgt_device **devt;
	struct list_head device_list;

	struct list_head cmd_hash_list[1 << HASH_ORDER];
	struct list_head cmd_list;
	struct tgt_cmd_queue cmd_queue;
};

static struct target *tgtt[MAX_NR_TARGET];
static struct target *hostt[MAX_NR_HOST];

#define QUEUE_FNS(bit, name)						\
static inline void set_queue_##name(struct tgt_cmd_queue *q)		\
{									\
	(q)->state |= (1UL << TGT_QUEUE_##bit);				\
}									\
static inline void clear_queue_##name(struct tgt_cmd_queue *q)		\
{									\
	(q)->state &= ~(1UL << TGT_QUEUE_##bit);			\
}									\
static inline int queue_##name(const struct tgt_cmd_queue *q)		\
{									\
	return ((q)->state & (1UL << TGT_QUEUE_##bit));			\
}

static inline int queue_active(const struct tgt_cmd_queue *q)		\
{									\
	return ((q)->active_cmd);					\
}

QUEUE_FNS(BLOCKED, blocked)
QUEUE_FNS(DELETED, deleted)

#define CMD_FNS(bit, name)						\
static inline void set_cmd_##name(struct cmd *c)			\
{									\
	(c)->state |= (1UL << TGT_CMD_##bit);				\
}									\
static inline void clear_cmd_##name(struct cmd *c)			\
{									\
	(c)->state &= ~(1UL << TGT_CMD_##bit);				\
}									\
static inline int cmd_##name(const struct cmd *c)			\
{									\
	return ((c)->state & (1UL << TGT_CMD_##bit));			\
}

CMD_FNS(QUEUED, queued)
CMD_FNS(PROCESSED, processed)
CMD_FNS(MGMT, mgmt)


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
	struct list_head *pos;

	list_for_each(pos, &target->device_list) {
		ent = list_entry(pos, struct tgt_device, dlist);
		if (dev->lun < ent->lun)
			break;
	}
	list_add(&dev->dlist, pos);
}

void tgt_cmd_queue_init(struct tgt_cmd_queue *q)
{
	q->active_cmd = 0;
	q->state = 0;
	INIT_LIST_HEAD(&q->queue);
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
	tgt_cmd_queue_init(&device->cmd_queue);

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

	dprintf("%u %" PRIu64 "\n", tid, dev_id);

	target = target_get(tid);
	if (!target)
		return -ENOENT;

	device = device_get(target, dev_id);
	if (!device) {
		eprintf("device %" PRIu64 " not found\n", dev_id);
		return -EINVAL;
	}

	if (!list_empty(&device->cmd_queue.queue))
		return -EBUSY;

	target->devt[dev_id] = NULL;
	if (device->addr)
		munmap((void *) (unsigned long) device->addr, device->size);

	close(device->fd);

	tgt_device_dir_delete(tid, dev_id);

	list_del(&device->dlist);

	free(device);
	return 0;
}

static int tgt_kspace_send_cmd(int nl_fd, struct cmd *cmd, int result, int rw)
{
	char resbuf[NLMSG_SPACE(sizeof(struct tgt_event))];
	struct tgt_event *ev_res = NLMSG_DATA(resbuf);

	ev_res->u.cmd_rsp.host_no = cmd->hostno;
	ev_res->u.cmd_rsp.cid = cmd->cid;
	ev_res->u.cmd_rsp.len = cmd->len;
	ev_res->u.cmd_rsp.result = result;
	ev_res->u.cmd_rsp.uaddr = cmd->uaddr;
	ev_res->u.cmd_rsp.rw = rw;

	return __nl_write(nl_fd, TGT_UEVENT_CMD_RSP, resbuf,
			  NLMSG_SPACE(sizeof(*ev_res)));
}

static int cmd_pre_perform(struct tgt_cmd_queue *q, struct cmd *cmd)
{
	int enabled = 0;

	if (cmd->attribute != MSG_SIMPLE_TAG)
		dprintf("non simple attribute %u %x %" PRIu64 " %d\n",
			cmd->cid, cmd->attribute, cmd->dev ? cmd->dev->lun : ~0ULL,
			q->active_cmd);

	switch (cmd->attribute) {
	case MSG_SIMPLE_TAG:
		if (!queue_blocked(q))
			enabled = 1;
		break;
	case MSG_ORDERED_TAG:
		if (!queue_blocked(q) && !queue_active(q))
			enabled = 1;
		break;
	case MSG_HEAD_TAG:
		enabled = 1;
		break;
	default:
		eprintf("unknown command attribute %x\n", cmd->attribute);
		cmd->attribute = MSG_ORDERED_TAG;
		if (!queue_blocked(q) && !queue_active(q))
			enabled = 1;
	}

	return enabled;
}

static void cmd_post_perform(struct tgt_cmd_queue *q, struct cmd *cmd,
			     unsigned long uaddr,
			     int len, uint8_t mmapped)
{
	cmd->uaddr = uaddr;
	cmd->len = len;
	cmd->mmapped = mmapped;

	q->active_cmd++;
	switch (cmd->attribute) {
	case MSG_ORDERED_TAG:
	case MSG_HEAD_TAG:
		set_queue_blocked(q);
		break;
	}
}

static void cmd_queue(struct tgt_event *ev_req, int nl_fd)
{
	struct target *target;
	struct tgt_cmd_queue *q;
	struct cmd *cmd;
	int result, enabled, len = 0;
	uint64_t offset, dev_id;
	uint8_t rw = 0, mmapped = 0;
	unsigned long uaddr = 0;

	target = host_to_target(ev_req->k.cmd_req.host_no);
	if (!target) {
		eprintf("%d is not bind to any target\n",
			ev_req->k.cmd_req.host_no);
		return;
	}

	/* TODO: preallocate cmd */
	cmd = calloc(1, sizeof(*cmd));
	cmd->hostno = ev_req->k.cmd_req.host_no;
 	cmd->cid = ev_req->k.cmd_req.cid;
	cmd->attribute = ev_req->k.cmd_req.attribute;
	cmd->tag = ev_req->k.cmd_req.tag;
	list_add(&cmd->clist, &target->cmd_list);
	list_add(&cmd->hlist, &target->cmd_hash_list[cmd_hashfn(cmd->cid)]);

	dev_id = scsi_get_devid(target->lid, ev_req->k.cmd_req.lun);
	dprintf("%u %x %" PRIx64 "\n", cmd->cid, ev_req->k.cmd_req.scb[0],
		dev_id);

	cmd->dev = device_get(target, dev_id);
	if (cmd->dev) {
		uaddr = target->devt[dev_id]->addr;
		q = &cmd->dev->cmd_queue;
	} else
		q = &target->cmd_queue;

	enabled = cmd_pre_perform(q, cmd);

	if (enabled) {
		result = scsi_cmd_perform(target->lid,
					  cmd->hostno, ev_req->k.cmd_req.scb,
					  &len, ev_req->k.cmd_req.data_len,
					  &uaddr, &rw, &mmapped, &offset,
					  ev_req->k.cmd_req.lun, cmd->dev,
					  &target->device_list);

		cmd_post_perform(q, cmd, uaddr, len, mmapped);

		dprintf("%u %x %lx %" PRIu64 " %d\n",
			cmd->cid, ev_req->k.cmd_req.scb[0], uaddr,
			offset, result);

		set_cmd_processed(cmd);
		tgt_kspace_send_cmd(nl_fd, cmd, result, rw);
	} else {
		set_cmd_queued(cmd);
		dprintf("blocked %u %x %" PRIu64 " %d\n",
			cmd->cid, ev_req->k.cmd_req.scb[0],
			cmd->dev ? cmd->dev->lun : ~0ULL,
			q->active_cmd);

		memcpy(cmd->scb, ev_req->k.cmd_req.scb, sizeof(cmd->scb));
		memcpy(cmd->lun, ev_req->k.cmd_req.lun, sizeof(cmd->lun));
		cmd->len = ev_req->k.cmd_req.data_len;
		list_add_tail(&cmd->qlist, &q->queue);
	}
}

static void post_cmd_done(int nl_fd, struct tgt_cmd_queue *q)
{
	struct cmd *cmd, *tmp;
	int enabled, result, len = 0;
	uint8_t rw = 0, mmapped = 0;
	uint64_t offset;
	unsigned long uaddr = 0;
	struct target *target;

	list_for_each_entry_safe(cmd, tmp, &q->queue, qlist) {
		enabled = cmd_pre_perform(q, cmd);
		if (enabled) {
			list_del(&cmd->qlist);
			target = host_to_target(cmd->hostno);
			if (!target) {
				eprintf("fail to find target!\n");
				exit(1);
			}
			dprintf("perform %u %x\n", cmd->cid, cmd->attribute);
			result = scsi_cmd_perform(target->lid,
						  cmd->hostno, cmd->scb,
						  &len,
						  cmd->len,
						  &uaddr,
						  &rw,
						  &mmapped,
						  &offset,
						  cmd->lun,
						  cmd->dev,
						  &target->device_list);
			cmd_post_perform(q, cmd, uaddr, len, mmapped);
			set_cmd_processed(cmd);
			tgt_kspace_send_cmd(nl_fd, cmd, result, rw);
		} else
			break;
	}
}

static struct cmd *find_cmd(struct target *target, uint32_t cid)
{
	struct cmd *cmd;
	struct list_head *head = &target->cmd_hash_list[cmd_hashfn(cid)];

	list_for_each_entry(cmd, head, hlist) {
		if (cmd->cid == cid)
			return cmd;
	}
	return NULL;
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

static void __cmd_done(struct target *target, struct cmd *cmd, int nl_fd)
{
	struct tgt_cmd_queue *q;
	int err, do_munmap;

	list_del(&cmd->clist);
	list_del(&cmd->hlist);

	do_munmap = cmd->mmapped;
	if (do_munmap) {
		if (!cmd->dev) {
			eprintf("device is null\n");
			exit(1);
		}

		if (cmd->dev->addr)
			do_munmap = 0;
	}
	err = scsi_cmd_done(do_munmap, !cmd->mmapped, cmd->uaddr, cmd->len);

	dprintf("%d %" PRIx64 " %u %d\n", cmd->mmapped, cmd->uaddr, cmd->len, err);

	if (cmd->dev)
		q = &cmd->dev->cmd_queue;
	else
		q = &target->cmd_queue;

	q->active_cmd--;
	switch (cmd->attribute) {
	case MSG_ORDERED_TAG:
	case MSG_HEAD_TAG:
		clear_queue_blocked(q);
		break;
	}

	free(cmd);

	post_cmd_done(nl_fd, q);
}

static int tgt_kspace_send_tsk_mgmt(int nl_fd, int host_no, uint64_t mid,
				    int result)
{
	char resbuf[NLMSG_SPACE(sizeof(struct tgt_event))];
	struct tgt_event *ev_res = NLMSG_DATA(resbuf);

	ev_res->u.tsk_mgmt_rsp.host_no = host_no;
	ev_res->u.tsk_mgmt_rsp.mid = mid;
	ev_res->u.tsk_mgmt_rsp.result = result;

	return __nl_write(nl_fd, TGT_UEVENT_TSK_MGMT_RSP, resbuf,
			  NLMSG_SPACE(sizeof(*ev_res)));
}

static void cmd_done(struct tgt_event *ev, int nl_fd)
{
	struct target *target;
	struct cmd *cmd;
	int host_no = ev->k.cmd_done.host_no;
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

	if (cmd_mgmt(cmd))
		tgt_kspace_send_tsk_mgmt(nl_fd, cmd->hostno, cmd->mid, -EEXIST);
	__cmd_done(target, cmd, nl_fd);
}

static int abort_task_by_tag(struct target* target, uint64_t tag, uint64_t mid,
			     int nl_fd)
{
	struct cmd *cmd, *tmp;

	eprintf("found %" PRIx64 " %" PRIx64 "\n", tag, mid);

	list_for_each_entry_safe(cmd, tmp, &target->cmd_list, clist) {
		if (cmd->tag == tag)
			goto found;
	}
	return -EEXIST;

found:
	eprintf("found %" PRIx64 " %lx\n", cmd->tag, cmd->state);
	if (cmd_processed(cmd)) {
		/*
		 * We've already sent this command to kernel space.
		 * We'll send the tsk mgmt response when we get the
		 * completion of this command.
		 */
		set_cmd_mgmt(cmd);
		cmd->mid = mid;
		return -EBUSY;
	} else {
		__cmd_done(target, cmd, nl_fd);
		tgt_kspace_send_cmd(nl_fd, cmd, TASK_ABORTED, 0);
	}

	return 0;
}

static void tsk_mgmt_req(struct tgt_event *ev_req, int nl_fd)
{
	struct target *target;
	int err = 0, send = 1;

	target = host_to_target(ev_req->k.cmd_req.host_no);
	if (!target) {
		eprintf("%d is not bind to any target\n",
			ev_req->k.cmd_req.host_no);
		return;
	}

	switch (ev_req->k.tsk_mgmt_req.function) {
	case ABORT_TASK:
		err = abort_task_by_tag(target, ev_req->k.tsk_mgmt_req.tag,
					ev_req->k.tsk_mgmt_req.mid, nl_fd);
		if (err == -EBUSY)
			send = 0;
		break;
	case ABORT_TASK_SET:
	case CLEAR_ACA:
	case CLEAR_TASK_SET:
	case LOGICAL_UNIT_RESET:
		eprintf("Not supported yet %x\n",
			ev_req->k.tsk_mgmt_req.function);
		break;
	default:
		eprintf("Unknown task management %x\n",
			ev_req->k.tsk_mgmt_req.function);
	}

	tgt_kspace_send_tsk_mgmt(nl_fd, ev_req->k.cmd_req.host_no,
				 ev_req->k.tsk_mgmt_req.mid, err);
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
		cmd_done(ev, nl_fd);
		break;
	case TGT_KEVENT_TSK_MGMT_REQ:
		tsk_mgmt_req(ev, nl_fd);
		break;
	default:
		eprintf("unknown event %u\n", nlh->nlmsg_type);
		exit(1);
	}
}

int tgt_target_bind(int tid, int host_no, int lid)
{
	int err;

	if (!tgtt[tid]) {
		eprintf("target is not found %d\n", tid);
		return -EINVAL;
	}
	tgtt[tid]->lid = lid;

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
	int err, i;
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
	INIT_LIST_HEAD(&target->cmd_list);
	for (i = 0; i < ARRAY_SIZE(target->cmd_hash_list); i++)
		INIT_LIST_HEAD(&target->cmd_hash_list[i]);

	INIT_LIST_HEAD(&target->device_list);

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

	tgt_cmd_queue_init(&target->cmd_queue);

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
	struct target *target = target_get(tid);

	if (!target)
		return -ENOENT;

	if (!list_empty(&target->device_list)) {
		eprintf("target %d still has devices\n", tid);
		return -EBUSY;
	}

	if (!list_empty(&target->cmd_queue.queue))
		return -EBUSY;

	free(target->devt);

	tgt_target_dir_attr_delete(tid, "hostno");
	tgt_target_dir_delete(tid);

	tgtt[tid] = NULL;
	free(target);

	return 0;
}
