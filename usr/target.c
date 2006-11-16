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
#include <sys/socket.h>
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

static struct cmd *cmd_lookup(struct target *target, uint64_t tag)
{
	struct cmd *cmd;
	struct list_head *list = &target->cmd_hash_list[hashfn(tag)];
	list_for_each_entry(cmd, list, c_hlist) {
		if (cmd->tag == tag)
			return cmd;
	}
	return NULL;
}

static void cmd_hlist_insert(struct target *target, struct cmd *cmd)
{
	struct list_head *list = &target->cmd_hash_list[hashfn(cmd->tag)];
	list_add(&cmd->c_hlist, list);
}

static void cmd_hlist_remove(struct cmd *cmd)
{
	list_del(&cmd->c_hlist);
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
	char *p;
	int dev_fd;
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

	p = strdup(path);
	if (!p)
		return -ENOMEM;

	device = tgt_drivers[target->lid]->bdt->bd_open(path, &dev_fd, &size);
	if (!device) {
		free(p);
		return -EINVAL;
	}

	device->fd = dev_fd;
	device->addr = 0;
	device->size = size;
	device->lun = dev_id;
	device->path = p;
	snprintf(device->scsi_id, sizeof(device->scsi_id),
		 "deadbeaf%d:%" PRIu64, tid, dev_id);

	tgt_cmd_queue_init(&device->cmd_queue);
	device_hlist_insert(target, device);
	device_list_insert(target, device);

	eprintf("Succeed to add a logical unit %" PRIu64 " to the target %d\n",
		dev_id, tid);

	return 0;
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

	free(device->path);
	device_hlist_remove(device);
	device_list_remove(device);

	tgt_drivers[target->lid]->bdt->bd_close(device);
	return 0;
}

static int cmd_enabled(struct tgt_cmd_queue *q, struct cmd *cmd)
{
	int enabled = 0;

	if (cmd->attribute != MSG_SIMPLE_TAG)
		dprintf("non simple attribute %" PRIx64 " %x %" PRIu64 " %d\n",
			cmd->tag, cmd->attribute, cmd->dev ? cmd->dev->lun : ~0ULL,
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
			     unsigned long uaddr, int len, uint8_t mmapped)
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

int target_cmd_queue(int host_no, uint8_t *scb, unsigned long uaddr,
		     uint8_t *lun, uint32_t data_len,
		     int attribute, uint64_t tag)
{
	struct target *target;
	struct tgt_cmd_queue *q;
	struct cmd *cmd;
	int result, enabled, async, len = 0;
	uint64_t offset, dev_id;
	uint8_t rw = 0, mmapped = 0;

	target = host_to_target(host_no);
	if (!target) {
		eprintf("%d is not bind to any target\n", host_no);
		return -ENOENT;
	}

	/* TODO: preallocate cmd */
	cmd = zalloc(sizeof(*cmd));
	if (!cmd)
		return -ENOMEM;

	cmd->c_target = target;
	cmd->hostno = host_no;
	cmd->attribute = attribute;
	cmd->tag = tag;
	cmd_hlist_insert(target, cmd);

	dev_id = scsi_get_devid(target->lid, lun);
	dprintf("%x %" PRIx64 "\n", scb[0], dev_id);

	cmd->dev = device_lookup(target, dev_id);
	if (cmd->dev)
		q = &cmd->dev->cmd_queue;
	else
		q = &target->cmd_queue;

	enabled = cmd_enabled(q, cmd);
	if (enabled) {
		result = scsi_cmd_perform(target->lid,
					  host_no, scb,
					  &len, data_len,
					  &uaddr, &rw, &mmapped, &offset,
					  lun, cmd->dev,
					  &target->device_list, &async, (void *) cmd);

		cmd_post_perform(q, cmd, uaddr, len, mmapped);

		dprintf("%" PRIx64 " %x %lx %" PRIu64 " %d %d %d\n",
			tag, scb[0], uaddr, offset, len, result, async);

		cmd->rw = rw;
		set_cmd_processed(cmd);
		if (!async)
			tgt_drivers[target->lid]->cmd_end_notify(host_no, len, result,
								 rw, uaddr, tag);
	} else {
		set_cmd_queued(cmd);
		dprintf("blocked %" PRIx64 " %x %" PRIu64 " %d\n",
			tag, scb[0], cmd->dev ? cmd->dev->lun : ~0ULL,
			q->active_cmd);

		memcpy(cmd->scb, scb, sizeof(cmd->scb));
		memcpy(cmd->lun, lun, sizeof(cmd->lun));
		cmd->len = data_len;
		cmd->uaddr = uaddr;
		list_add_tail(&cmd->qlist, &q->queue);
	}

	return 0;
}

void target_cmd_io_done(void *key, int result)
{
	struct cmd *cmd = (struct cmd *) key;

	/* TODO: sense in case of error. */
	tgt_drivers[cmd->c_target->lid]->cmd_end_notify(cmd->hostno,
							cmd->len, result,
							cmd->rw, cmd->uaddr,
							cmd->tag);
	return;
}

static void post_cmd_done(struct tgt_cmd_queue *q)
{
	struct cmd *cmd, *tmp;
	int enabled, result, async, len = 0;
	uint8_t rw = 0, mmapped = 0;
	uint64_t offset;

	list_for_each_entry_safe(cmd, tmp, &q->queue, qlist) {
		enabled = cmd_enabled(q, cmd);
		if (enabled) {
			list_del(&cmd->qlist);
			dprintf("perform %" PRIx64 " %x\n", cmd->tag, cmd->attribute);
			result = scsi_cmd_perform(cmd->c_target->lid,
						  cmd->hostno, cmd->scb,
						  &len, cmd->len,
						  (unsigned long *) &cmd->uaddr,
						  &rw, &mmapped, &offset,
						  cmd->lun, cmd->dev,
						  &cmd->c_target->device_list,
						  &async, (void *) cmd);
			cmd->rw = rw;
			cmd_post_perform(q, cmd, cmd->uaddr, len, mmapped);
			set_cmd_processed(cmd);
			if (!async)
				tgt_drivers[cmd->c_target->lid]->cmd_end_notify(cmd->hostno,
										len,
										result,
										rw,
										cmd->uaddr,
										cmd->tag);
		} else
			break;
	}
}

static void __cmd_done(struct target *target, struct cmd *cmd)
{
	struct tgt_cmd_queue *q;
	int err, do_munmap;

	cmd_hlist_remove(cmd);

	do_munmap = cmd->mmapped;
	if (do_munmap) {
		if (!cmd->dev) {
			eprintf("device is null\n");
			exit(1);
		}

		if (cmd->dev->addr)
			do_munmap = 0;
	}
	err = tgt_drivers[target->lid]->bdt->bd_cmd_done(do_munmap,
							 !cmd->mmapped,
							 cmd->uaddr, cmd->len);

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

void target_cmd_done(int host_no, uint64_t tag)
{
	struct target *target;
	struct cmd *cmd;
	struct mgmt_req *mreq;

	target = host_to_target(host_no);
	if (!target) {
		eprintf("%d is not bind to any target\n", host_no);
		return;
	}

	cmd = cmd_lookup(target, tag);
	if (!cmd) {
		eprintf("Cannot find cmd %d %" PRIx64 "\n", host_no, tag);
		return;
	}

	mreq = cmd->mreq;
	if (mreq && !--mreq->busy) {
		int err = mreq->function == ABORT_TASK ? -EEXIST : 0;
		tgt_drivers[cmd->c_target->lid]->mgmt_end_notify(cmd->hostno,
								 mreq->mid, err);
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
		tgt_drivers[cmd->c_target->lid]->cmd_end_notify(cmd->hostno, 0,
								TASK_ABORTED, 0, 0, cmd->tag);
	}
	return err;
}

static int abort_task_set(struct mgmt_req *mreq, struct target* target, int host_no,
			  uint64_t tag, uint8_t *lun, int all)
{
	struct cmd *cmd, *tmp;
	int i, err, count = 0;

	eprintf("found %" PRIx64 " %d\n", tag, all);

	for (i = 0; i < ARRAY_SIZE(target->cmd_hash_list); i++) {
		struct list_head *list = &target->cmd_hash_list[i];
		list_for_each_entry_safe(cmd, tmp, list, c_hlist) {
			if ((all && cmd->hostno == host_no) ||
			    (cmd->tag == tag && cmd->hostno == host_no) ||
			    (lun && !memcmp(cmd->lun, lun, sizeof(cmd->lun)))) {
				err = abort_cmd(target, mreq, cmd);
				if (err)
					mreq->busy++;
				count++;
			}
		}
	}

	return count;
}

void target_mgmt_request(int host_no, uint64_t req_id, int function,
			 uint8_t *lun, uint64_t tag)
{
	struct target *target;
	struct mgmt_req *mreq;
	int err = 0, count, send = 1;

	target = host_to_target(host_no);
	if (!target) {
		eprintf("%d is not bind to any target\n", host_no);
		return;
	}

	mreq = zalloc(sizeof(*mreq));
	if (!mreq)
		return;
	mreq->mid = req_id;
	mreq->function = function;

	switch (function) {
	case ABORT_TASK:
		count = abort_task_set(mreq, target, host_no, tag, NULL, 0);
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
		eprintf("Not supported yet %x\n", function);
		err = -EINVAL;
		break;
	case LOGICAL_UNIT_RESET:
		count = abort_task_set(mreq, target, host_no, 0, lun, 0);
		if (mreq->busy)
			send = 0;
		break;
	default:
		err = -EINVAL;
		eprintf("Unknown task management %x\n", function);
	}

	if (send) {
		tgt_drivers[target->lid]->mgmt_end_notify(host_no, req_id, err);
		free(mreq);
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

	target = zalloc(sizeof(*target));
	if (!target)
		return -ENOMEM;

	target->tid = tid;
	for (i = 0; i < ARRAY_SIZE(target->cmd_hash_list); i++)
		INIT_LIST_HEAD(&target->cmd_hash_list[i]);

	INIT_LIST_HEAD(&target->device_list);
	for (i = 0; i < ARRAY_SIZE(target->device_hash_list); i++)
		INIT_LIST_HEAD(&target->device_hash_list[i]);

	target->target_state = SCSI_TARGET_SUSPENDED;

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

enum scsi_target_state tgt_get_target_state(int tid)
{
	struct target *target;

	target = target_lookup(tid);
	if (!target)
		return -ENOENT;
	return target->target_state;
}

static struct {
	enum scsi_target_state value;
	char *name;
} target_state[] = {
	{SCSI_TARGET_SUSPENDED, "suspended"},
	{SCSI_TARGET_RUNNING, "running"},
};

static char *target_state_state_name(enum scsi_target_state state)
{
	int i;
	char *name = NULL;

	for (i = 0; i < ARRAY_SIZE(target_state); i++) {
		if (target_state[i].value == state) {
			name = target_state[i].name;
			break;
		}
	}
	return name;
}

int tgt_set_target_state(int tid, char *str)
{
	int i, err = -EINVAL;
	struct target *target;

	target = target_lookup(tid);
	if (!target)
		return -ENOENT;

	for (i = 0; i < ARRAY_SIZE(target_state); i++) {
		if (!strcmp(target_state[i].name, str)) {
			target->target_state = target_state[i].value;
			err = 0;
			break;
		}
	}

	return err;
}

int tgt_target_show_all(char *buf, int rest)
{
	int i, len, total;
	struct target *target;
	struct tgt_device *device;

	for (i = total = 0; i < ARRAY_SIZE(target_hash_list); i++) {
		list_for_each_entry(target, &target_hash_list[i], t_hlist) {
			len = snprintf(buf, rest, "tid %d: lld name %s: state %s\n",
				       target->tid, tgt_drivers[target->lid]->name,
				       target_state_state_name(target->target_state));
			buf += len;
			total += len;
			rest -= len;
			if (!rest)
				goto out;

			list_for_each_entry(device, &target->device_list, d_list) {
				len = snprintf(buf, rest, "\tlun %" PRIu64 ": path %s\n",
					       device->lun, device->path);
				buf += len;
				total += len;
				rest -= len;
				if (!rest)
					goto out;
			}
		}
	}
out:
	return total;
}

__attribute__((constructor)) static void target_init(void)
{
	int i;
	for (i = 0; i < ARRAY_SIZE(target_hash_list); i++)
		INIT_LIST_HEAD(&target_hash_list[i]);
}
