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
#include <sys/stat.h>

#include <linux/fs.h>
#include <scsi/scsi.h>

#include "list.h"
#include "util.h"
#include "tgtd.h"
#include "driver.h"
#include "target.h"

static struct target *hostt[MAX_NR_HOST];
static struct list_head target_hash_list[1 << HASH_ORDER];

static struct target *target_lookup(int tid)
{
	struct target *target;

	list_for_each_entry(target, &target_hash_list[hashfn(tid)], t_hlist)
		if (target->tid == tid)
			return target;
	return NULL;
}

static void target_hlist_insert(struct target *target)
{
	struct list_head *list = &target_hash_list[hashfn(target->tid)];
	list_add(&target->t_hlist, list);
}

static void target_hlist_remove(struct target *target)
{
	list_del(&target->t_hlist);
}

static struct tgt_device *device_lookup(struct target *target, uint64_t dev_id)
{
	struct tgt_device *device;
	struct list_head *list = &target->device_hash_list[hashfn(dev_id)];
	list_for_each_entry(device, list, d_hlist)
		if (device->lun == dev_id)
			return device;
	return NULL;
}

static void device_hlist_insert(struct target *target, struct tgt_device *device)
{
	struct list_head *list = &target->device_hash_list[hashfn(device->lun)];
	list_add(&device->d_hlist, list);
}

static void device_hlist_remove(struct tgt_device *device)
{
	list_del(&device->d_hlist);
}

static void device_list_insert(struct target *target, struct tgt_device *device)
{
	struct tgt_device *pos;
	list_for_each_entry(pos, &target->device_list, d_list) {
		if (device->lun < pos->lun)
			break;
	}
	list_add(&device->d_list, &pos->d_list);
}

static void device_list_remove(struct tgt_device *device)
{
	list_del(&device->d_list);
}

static struct target *host_to_target(int host_no)
{
	if (host_no < MAX_NR_HOST)
		return hostt[host_no];

	return NULL;
}

static void tgt_cmd_queue_init(struct tgt_cmd_queue *q)
{
	q->active_cmd = 0;
	q->state = 0;
	INIT_LIST_HEAD(&q->queue);
}

int tgt_device_create(int tid, uint64_t dev_id, char *path)
{
	struct target *target;
	struct tgt_device *device;
	struct stat64 st;
	int err, dev_fd;
	uint64_t size;

	dprintf("%d %" PRIu64 " %s\n", tid, dev_id, path);

	target = target_lookup(tid);
	if (!target)
		return -ENOENT;

	device = device_lookup(target, dev_id);
	if (device) {
		eprintf("device %" PRIu64 " already exists\n", dev_id);
		return -EINVAL;
	}

	dev_fd = open(path, O_RDWR | O_LARGEFILE);
	if (dev_fd < 0) {
		eprintf("Could not open %s %s\n", path, strerror(errno));
		return dev_fd;
	}

	err = fstat64(dev_fd, &st);
	if (err < 0) {
		printf("Cannot get stat %d %s\n", dev_fd, strerror(errno));
		goto close_dev_fd;
	}

	if (S_ISREG(st.st_mode))
		size = st.st_size;
	else if(S_ISBLK(st.st_mode)) {
		err = ioctl(dev_fd, BLKGETSIZE64, &size);
		if (err < 0) {
			eprintf("Cannot get size %s\n", strerror(errno));
			goto close_dev_fd;
		}
	} else {
		eprintf("Cannot use this mode %x\n", st.st_mode);
		goto close_dev_fd;
	}

	device = malloc(sizeof(*device));
	if (!device)
		goto close_dev_fd;

	device->fd = dev_fd;
	device->addr = 0;
	device->size = size;
	device->lun = dev_id;
	snprintf(device->scsi_id, sizeof(device->scsi_id),
		 "deadbeaf%d:%" PRIu64, tid, dev_id);

	tgt_cmd_queue_init(&device->cmd_queue);
	device_hlist_insert(target, device);
	device_list_insert(target, device);

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

	target = target_lookup(tid);
	if (!target)
		return -ENOENT;

	device = device_lookup(target, dev_id);
	if (!device) {
		eprintf("device %" PRIu64 " not found\n", dev_id);
		return -EINVAL;
	}

	if (!list_empty(&device->cmd_queue.queue))
		return -EBUSY;

	close(device->fd);
	device_hlist_remove(device);
	device_list_remove(device);

	free(device);
	return 0;
}

static int tgt_kspace_send_cmd(struct cmd *cmd, int result, int rw)
{
	struct tgt_event ev;

	ev.type = TGT_UEVENT_CMD_RSP;
	ev.u.cmd_rsp.host_no = cmd->hostno;
	ev.u.cmd_rsp.cid = cmd->cid;
	ev.u.cmd_rsp.len = cmd->len;
	ev.u.cmd_rsp.result = result;
	ev.u.cmd_rsp.uaddr = cmd->uaddr;
	ev.u.cmd_rsp.rw = rw;

	return kreq_send(&ev);
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

static void cmd_queue(struct tgt_event *ev_req)
{
	struct target *target;
	struct tgt_cmd_queue *q;
	struct cmd *cmd;
	int result, enabled, len = 0;
	uint64_t offset, dev_id;
	uint8_t rw = 0, mmapped = 0;
	unsigned long uaddr = 0;
	int hostno = ev_req->k.cmd_req.host_no;

	target = host_to_target(hostno);
	if (!target) {
		int tid, lid = 0, err = -1;
		if (tgt_drivers[lid]->target_bind) {
			tid = tgt_drivers[0]->target_bind(hostno);
			if (tid >= 0) {
				err = tgt_target_bind(tid, hostno, lid);
				if (!err)
					target = host_to_target(hostno);
			}
		}

		if (!target) {
			eprintf("%d is not bind to any target\n",
				ev_req->k.cmd_req.host_no);
			return;
		}
	}

	/* TODO: preallocate cmd */
	cmd = calloc(1, sizeof(*cmd));
	cmd->hostno = ev_req->k.cmd_req.host_no;
 	cmd->cid = ev_req->k.cmd_req.cid;
	cmd->attribute = ev_req->k.cmd_req.attribute;
	cmd->tag = ev_req->k.cmd_req.tag;
	list_add(&cmd->clist, &target->cmd_list);
	list_add(&cmd->hlist, &target->cmd_hash_list[hashfn(cmd->cid)]);

	dev_id = scsi_get_devid(target->lid, ev_req->k.cmd_req.lun);
	dprintf("%u %x %" PRIx64 "\n", cmd->cid, ev_req->k.cmd_req.scb[0],
		dev_id);

	cmd->dev = device_lookup(target, dev_id);
	if (cmd->dev) {
		uaddr = cmd->dev->addr;
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
		tgt_kspace_send_cmd(cmd, result, rw);
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

static void post_cmd_done(struct tgt_cmd_queue *q)
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
			tgt_kspace_send_cmd(cmd, result, rw);
		} else
			break;
	}
}

static struct cmd *find_cmd(struct target *target, uint32_t cid)
{
	struct cmd *cmd;
	struct list_head *head = &target->cmd_hash_list[hashfn(cid)];

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

static void __cmd_done(struct target *target, struct cmd *cmd)
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

	post_cmd_done(q);
}

static int tgt_kspace_send_tsk_mgmt(int host_no, uint64_t mid, int result)
{
	struct tgt_event ev;

	ev.u.tsk_mgmt_rsp.host_no = host_no;
	ev.u.tsk_mgmt_rsp.mid = mid;
	ev.u.tsk_mgmt_rsp.result = result;

	return kreq_send(&ev);
}

static void cmd_done(struct tgt_event *ev)
{
	struct target *target;
	struct cmd *cmd;
	struct mgmt_req *mreq;
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

	mreq = cmd->mreq;
	if (mreq && !--mreq->busy) {
		int err = mreq->function == ABORT_TASK ? -EEXIST : 0;
		tgt_kspace_send_tsk_mgmt(cmd->hostno, mreq->mid, err);
		free(mreq);
	}

	__cmd_done(target, cmd);
}

static int abort_cmd(struct target* target, struct mgmt_req *mreq,
		     struct cmd *cmd)
{
	int err = 0;

	eprintf("found %" PRIx64 " %lx\n", cmd->tag, cmd->state);

	if (cmd_processed(cmd)) {
		/*
		 * We've already sent this command to kernel space.
		 * We'll send the tsk mgmt response when we get the
		 * completion of this command.
		 */
		cmd->mreq = mreq;
		err = -EBUSY;
	} else {
		__cmd_done(target, cmd);
		tgt_kspace_send_cmd(cmd, TASK_ABORTED, 0);
	}
	return err;
}

static int abort_task_set(struct mgmt_req *mreq, struct target* target, int host_no,
			  uint64_t tag, uint8_t *lun, int all)
{
	struct cmd *cmd, *tmp;
	int err, count = 0;

	eprintf("found %" PRIx64 " %d\n", tag, all);

	list_for_each_entry_safe(cmd, tmp, &target->cmd_list, clist) {
		if ((all && cmd->hostno == host_no)||
		    (cmd->tag == tag && cmd->hostno == host_no) ||
		    (lun && !memcmp(cmd->lun, lun, sizeof(cmd->lun)))) {
			err = abort_cmd(target, mreq, cmd);
			if (err)
				mreq->busy++;
			count++;
		}
	}

	return count;
}

static void tsk_mgmt_req(struct tgt_event *ev_req)
{
	struct target *target;
	struct mgmt_req *mreq;
	int err = 0, count, send = 1;
	int host_no = ev_req->k.cmd_req.host_no;

	target = host_to_target(host_no);
	if (!target) {
		eprintf("%d is not bind to any target\n",
			ev_req->k.cmd_req.host_no);
		return;
	}

	mreq = calloc(1, sizeof(*mreq));
	mreq->mid = ev_req->k.tsk_mgmt_req.mid;
	mreq->function = ev_req->k.tsk_mgmt_req.function;

	switch (mreq->function) {
	case ABORT_TASK:
		count = abort_task_set(mreq, target, host_no,
				       ev_req->k.tsk_mgmt_req.tag,
				       NULL, 0);
		if (mreq->busy)
			send = 0;
		if (!count)
			err = -EEXIST;
		break;
	case ABORT_TASK_SET:
		count = abort_task_set(mreq, target, host_no, 0, NULL, 1);
		if (mreq->busy)
			send = 0;
		break;
	case CLEAR_ACA:
	case CLEAR_TASK_SET:
		eprintf("Not supported yet %x\n",
			ev_req->k.tsk_mgmt_req.function);
		err = -EINVAL;
		break;
	case LOGICAL_UNIT_RESET:
		count = abort_task_set(mreq, target, host_no, 0,
				       ev_req->k.tsk_mgmt_req.lun, 0);
		if (mreq->busy)
			send = 0;
		break;
	default:
		err = -EINVAL;
		eprintf("Unknown task management %x\n",
			ev_req->k.tsk_mgmt_req.function);
	}

	if (send) {
		tgt_kspace_send_tsk_mgmt(ev_req->k.cmd_req.host_no,
					 ev_req->k.tsk_mgmt_req.mid, err);
		free(mreq);
	}
}

void kreq_exec(struct tgt_event *ev)
{
	dprintf("event %u\n", ev->type);

	switch (ev->type) {
	case TGT_KEVENT_CMD_REQ:
		cmd_queue(ev);
		break;
	case TGT_KEVENT_CMD_DONE:
		cmd_done(ev);
		break;
	case TGT_KEVENT_TSK_MGMT_REQ:
		tsk_mgmt_req(ev);
		break;
	default:
		eprintf("unknown event %u\n", ev->type);
		exit(1);
	}
}

int tgt_target_bind(int tid, int host_no, int lid)
{
	struct target *target;

	target = target_lookup(tid);
	if (!target) {
		eprintf("target is not found %d\n", tid);
		return -EINVAL;
	}
	target->lid = lid;

	if (hostt[host_no]) {
		eprintf("host is already binded %d %d\n", tid, host_no);
		return -EINVAL;
	}

	eprintf("Succeed to bind the target %d to the scsi host %d\n",
		tid, host_no);
	hostt[host_no] = target;
	return 0;
}

int tgt_target_create(int tid)
{
	int i;
	struct target *target;

	target = target_lookup(tid);
	if (target) {
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
	for (i = 0; i < ARRAY_SIZE(target->device_hash_list); i++)
		INIT_LIST_HEAD(&target->device_hash_list[i]);

	tgt_cmd_queue_init(&target->cmd_queue);
	target_hlist_insert(target);

	eprintf("Succeed to create a new target %d\n", tid);

	return 0;
}

int tgt_target_destroy(int tid)
{
	struct target *target;

	target = target_lookup(tid);
	if (!target)
		return -ENOENT;

	if (!list_empty(&target->device_list)) {
		eprintf("target %d still has devices\n", tid);
		return -EBUSY;
	}

	if (!list_empty(&target->cmd_queue.queue))
		return -EBUSY;

	target_hlist_remove(target);
	free(target);

	return 0;
}
