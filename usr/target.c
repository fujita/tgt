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

#include "list.h"
#include "util.h"
#include "tgtd.h"
#include "driver.h"
#include "target.h"
#include "scsi.h"
#include "tgtadm.h"

static struct target *hostt[MAX_NR_HOST];
static struct list_head target_hash_list[1 << HASH_ORDER];
static LIST_HEAD(target_list);

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

static struct tgt_device *device_lookup(struct target *target, uint64_t lun)
{
	struct tgt_device *device;

	list_for_each_entry(device, &target->device_list, device_siblings)
		if (device->lun == lun)
			return device;
	return NULL;
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

static int tgt_device_path_update(struct target *target,
				  struct tgt_device *device, char *path)
{
	int err, dev_fd;
	uint64_t size;

	path = strdup(path);
	if (!path)
		return TGTADM_NOMEM;

	err = target->bdt->bd_open(device, path, &dev_fd, &size);
	if (err) {
		free(path);
		return TGTADM_INVALID_REQUEST;
	}

	device->fd = dev_fd;
	device->addr = 0;
	device->size = size;
	device->path = path;

	return 0;
}

static struct tgt_device *
__device_lookup(int tid, uint64_t lun, struct target **t)
{
	struct target *target;
	struct tgt_device *device;

	target = target_lookup(tid);
	if (!target)
		return NULL;

	device = device_lookup(target, lun);
	if (!device)
		return NULL;

	*t = target;
	return device;
}

int tgt_device_create(int tid, uint64_t lun, char *args)
{
	char *p;
	int err;
	struct target *target;
	struct tgt_device *device, *pos;

	dprintf("%d %" PRIu64 "\n", tid, lun);

	target = target_lookup(tid);
	if (!target)
		return TGTADM_NO_TARGET;

	device = device_lookup(target, lun);
	if (device) {
		eprintf("device %" PRIu64 " already exists\n", lun);
		return TGTADM_LUN_EXIST;
	}

	if (!*args)
		return TGTADM_INVALID_REQUEST;

	p = strchr(args, '=');
	if (!p)
		return TGTADM_INVALID_REQUEST;
	p++;

	device = zalloc(sizeof(*device) + target->bdt->bd_datasize);
	if (!device)
		return TGTADM_NOMEM;

	err = tgt_device_path_update(target, device, p);
	if (err) {
		free(device);
		return err;
	}

	device->lun = lun;

	snprintf(device->scsi_id, sizeof(device->scsi_id),
		 "deadbeaf%d:%" PRIu64, tid, lun);

	tgt_cmd_queue_init(&device->cmd_queue);

	list_for_each_entry(pos, &target->device_list, device_siblings) {
		if (device->lun < pos->lun)
			break;
	}
	list_add_tail(&device->device_siblings, &pos->device_siblings);

	dprintf("Add a logical unit %" PRIu64 " to the target %d\n", lun, tid);
	return 0;
}

int tgt_device_destroy(int tid, uint64_t lun)
{
	struct target *target;
	struct tgt_device *device;

	dprintf("%u %" PRIu64 "\n", tid, lun);

	device = __device_lookup(tid, lun, &target);
	if (!device) {
		eprintf("device %" PRIu64 " not found\n", lun);
		return TGTADM_NO_LUN;
	}

	if (!list_empty(&device->cmd_queue.queue))
		return TGTADM_LUN_ACTIVE;

	free(device->path);
	list_del(&device->device_siblings);

	target->bdt->bd_close(device);
	free(device);
	return 0;
}

int device_reserve(int tid, uint64_t lun, uint64_t reserve_id)
{
	struct target *target;
	struct tgt_device *device;

	device = __device_lookup(tid, lun, &target);
	if (!device)
		return -EINVAL;

	if (device->reserve_id && device->reserve_id != reserve_id) {
		dprintf("already reserved %" PRIu64 " %" PRIu64 "\n",
			device->reserve_id, reserve_id);
		return -EBUSY;
	}

	device->reserve_id = reserve_id;
	return 0;
}

int device_release(int tid, uint64_t lun, uint64_t reserve_id, int force)
{
	struct target *target;
	struct tgt_device *device;

	device = __device_lookup(tid, lun, &target);
	if (!device)
		return 0;

	if (force || device->reserve_id == reserve_id) {
		device->reserve_id = 0;
		return 0;
	}

	return -EBUSY;
}

int device_reserved(int tid, uint64_t lun, uint64_t reserve_id)
{
	struct target *target;
	struct tgt_device *device;

	device = __device_lookup(tid, lun, &target);
	if (!device || !device->reserve_id || device->reserve_id == reserve_id)
		return 0;
	return -EBUSY;
}

int tgt_device_update(int tid, uint64_t dev_id, char *name)
{
	int err = 0;
	struct target *target;
	struct tgt_device *device;

	target = target_lookup(tid);
	if (!target)
		return TGTADM_NO_TARGET;

	device = device_lookup(target, dev_id);
	if (!device) {
		eprintf("device %" PRIu64 " not found\n", dev_id);
		return TGTADM_NO_LUN;
	}

	if (!strcmp(name, "scsi_id="))
		memcpy(device->scsi_id, name + 8, sizeof(device->scsi_id) - 1);
	else if (!strcmp(name, "scsi_sn="))
		memcpy(device->scsi_sn, name + 8, sizeof(device->scsi_sn) - 1);
	else
		err = TGTADM_INVALID_REQUEST;

	return err;
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

int target_cmd_queue(int host_no, uint8_t *scb, uint8_t rw,
		     unsigned long uaddr,
		     uint8_t *lun, uint32_t data_len,
		     int attribute, uint64_t tag)
{
	struct target *target;
	struct tgt_cmd_queue *q;
	struct cmd *cmd;
	int result, enabled = 0, async, len = 0;
	uint64_t offset, dev_id;
	uint8_t mmapped = 0;

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

	/* FIXME */
	if (target->target_iotype == SCSI_TARGET_RAWIO) {
		memcpy(cmd->scb, scb, sizeof(cmd->scb));
		dprintf("%u %s\n", scb[0], cmd->dev ? "do sg" : "fake");

		/* we can't pass through REPORT_LUNS. */
		if (cmd->dev && scb[0] != REPORT_LUNS) {
			target->bdt->bd_cmd_submit(cmd->dev, cmd->scb, rw,
						   data_len, &uaddr, offset,
						   &async, (void *) cmd);
			cmd->len = data_len;
			cmd->uaddr = uaddr;
			goto out;
		} else
			enabled = 1;
	}

	if (cmd->dev)
		q = &cmd->dev->cmd_queue;
	else
		q = &target->cmd_queue;

	if (!enabled)
		enabled = cmd_enabled(q, cmd);

	if (enabled) {
		result = scsi_cmd_perform(target->tid, target->lid,
					  host_no, scb,
					  &len, data_len,
					  &uaddr, &rw, &mmapped, &offset,
					  lun, cmd->dev,
					  &target->device_list, &async, (void *) cmd,
					  target->bdt->bd_cmd_submit);

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
out:
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
			result = scsi_cmd_perform(cmd->c_target->tid,
						  cmd->c_target->lid,
						  cmd->hostno, cmd->scb,
						  &len, cmd->len,
						  (unsigned long *) &cmd->uaddr,
						  &rw, &mmapped, &offset,
						  cmd->lun, cmd->dev,
						  &cmd->c_target->device_list,
						  &async, (void *) cmd,
						  cmd->c_target->bdt->bd_cmd_submit);
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
	err = target->bdt->bd_cmd_done(do_munmap,
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
		device_release(target->tid, scsi_get_devid(target->lid, lun),
			       host_no, 1);
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

int it_nexus_create(int tid, uint32_t nid)
{
	struct target *target;
	struct it_nexus *nexus;

	target = target_lookup(tid);
	if (!target)
		return -ENOENT;

	list_for_each_entry(nexus, &target->it_nexus_list, nexus_siblings) {
		if (nexus->nexus_id == nid)
			return -EEXIST;
	}

	nexus = zalloc(sizeof(*nexus));
	if (!nexus)
		return -ENOMEM;

	nexus->nexus_id = nid;
	nexus->nexus_target = target;
	list_add_tail(&nexus->nexus_siblings, &target->it_nexus_list);

	return 0;
}

int it_nexus_destroy(int tid, uint32_t nid)
{
	struct target *target;
	struct it_nexus *nexus, *tmp;

	target = target_lookup(tid);
	if (!target)
		return -ENOENT;

	list_for_each_entry_safe(nexus, tmp, &target->it_nexus_list,
				 nexus_siblings) {
		if (nexus->nexus_id == nid) {
			list_del(&nexus->nexus_siblings);
			free(nexus);
			return 0;
		}
	}
	return -ENOENT;
}

struct account_entry {
	int aid;
	char *user;
	char *password;
	struct list_head ac_list;
};

static LIST_HEAD(accounts_list);

static struct account_entry *__account_lookup_id(int aid)
{
	struct account_entry *ac;

	list_for_each_entry(ac, &accounts_list, ac_list)
		if (ac->aid == aid)
			return ac;
	return NULL;
}

static struct account_entry *__account_lookup_user(char *user)
{
	struct account_entry *ac;

	list_for_each_entry(ac, &accounts_list, ac_list)
		if (!strcmp(ac->user, user))
			return ac;
	return NULL;
}

int account_lookup(int tid, int type, char *user, char *password, int plen)
{
	int i;
	struct target *target;
	struct account_entry *ac;

	target = target_lookup(tid);
	if (!target)
		return -ENOENT;

	if (type == ACCOUNT_TYPE_INCOMING) {
		for (i = 0; target->account.nr_inaccount; i++) {
			ac = __account_lookup_id(target->account.in_aids[i]);
			if (ac) {
				if (!strcmp(ac->user, user))
					goto found;
			}
		}
	} else {
		ac = __account_lookup_id(target->account.out_aid);
		if (ac)
			goto found;
	}

	return -ENOENT;
found:
	strncpy(password, ac->password, plen);
	return 0;
}

int account_add(char *user, char *password)
{
	int aid;
	struct account_entry *ac;

	ac = __account_lookup_user(user);
	if (ac)
		return TGTADM_USER_EXIST;

	for (aid = 1; __account_lookup_id(aid) && aid < INT_MAX; aid++)
		;
	if (aid == INT_MAX)
		return TGTADM_TOO_MANY_USER;

	ac = zalloc(sizeof(*ac));
	if (!ac)
		return TGTADM_NOMEM;

	ac->aid = aid;
	ac->user = strdup(user);
	if (!ac->user)
		goto free_account;

	ac->password = strdup(password);
	if (!ac->password)
		goto free_username;

	list_add(&ac->ac_list, &accounts_list);
	return 0;
free_username:
	free(ac->user);
free_account:
	free(ac);
	return TGTADM_NOMEM;
}

static int __inaccount_bind(struct target *target, int aid)
{
	int i;

	/* first, check whether we already have this account. */
	for (i = 0; i < target->account.max_inaccount; i++)
		if (target->account.in_aids[i] == aid)
			return TGTADM_USER_EXIST;

	if (target->account.nr_inaccount < target->account.max_inaccount) {
		for (i = 0; i < target->account.max_inaccount; i++)
			if (!target->account.in_aids[i])
				break;
		if (i == target->account.max_inaccount) {
			eprintf("bug %d\n", target->account.max_inaccount);
			return TGTADM_UNKNOWN_ERR;
		}

		target->account.in_aids[i] = aid;
		target->account.nr_inaccount++;
	} else {
		int new_max = target->account.max_inaccount << 1;
		int *buf;

		buf = zalloc(new_max * sizeof(int));
		if (!buf)
			return TGTADM_NOMEM;

		memcpy(buf, target->account.in_aids,
		       target->account.max_inaccount * sizeof(int));
		free(target->account.in_aids);
		target->account.in_aids = buf;
		target->account.in_aids[target->account.max_inaccount] = aid;
		target->account.max_inaccount = new_max;
	}

	return 0;
}

int account_ctl(int tid, int type, char *user, int bind)
{
	struct target *target;
	struct account_entry *ac;
	int i, err = 0;

	target = target_lookup(tid);
	if (!target)
		return TGTADM_NO_TARGET;

	ac = __account_lookup_user(user);
	if (!ac)
		return TGTADM_NO_USER;

	if (bind) {
		if (type == ACCOUNT_TYPE_INCOMING)
			err = __inaccount_bind(target, ac->aid);
		else {
			if (target->account.out_aid)
				err = TGTADM_OUTACCOUNT_EXIST;
			else
				target->account.out_aid = ac->aid;
		}
	} else
		if (type == ACCOUNT_TYPE_INCOMING) {
			for (i = 0; i < target->account.max_inaccount; i++)
				if (target->account.in_aids[i] == ac->aid) {
					target->account.in_aids[i] = 0;
					target->account.nr_inaccount--;
					break;
				}

			if (i == target->account.max_inaccount)
				err = TGTADM_NO_USER;
		} else
			if (target->account.out_aid)
				target->account.out_aid = 0;
			else
				err = TGTADM_NO_USER;

	return err;
}

void account_del(char *user)
{
	struct account_entry *ac;
	struct target *target;

	ac = __account_lookup_user(user);
	if (!ac)
		return;

	list_for_each_entry(target, &target_list, t_list) {
		account_ctl(target->tid, ACCOUNT_TYPE_INCOMING, ac->user, 0);
		account_ctl(target->tid, ACCOUNT_TYPE_OUTGOING, ac->user, 0);
	}

	list_del(&ac->ac_list);
	free(ac->user);
	free(ac->password);
	free(ac);
}

int account_available(int tid, int dir)
{
	struct target *target;

	target = target_lookup(tid);
	if (!target)
		return 0;

	if (dir == ACCOUNT_TYPE_INCOMING)
		return target->account.nr_inaccount;
	else
		return target->account.out_aid;
}

int acl_add(int tid, char *address)
{
	char *str;
	struct target *target;
	struct acl_entry *acl, *tmp;

	target = target_lookup(tid);
	if (!target)
		return TGTADM_NO_TARGET;

	list_for_each_entry_safe(acl, tmp, &target->acl_list, aclent_list)
		if (!strcmp(address, acl->address))
			return TGTADM_ACL_EXIST;

	acl = zalloc(sizeof(*acl));
	if (!acl)
		return TGTADM_NOMEM;

	str = strdup(address);
	if (!str) {
		free(acl);
		return TGTADM_NOMEM;
	}

	acl->address = str;
	list_add_tail(&acl->aclent_list, &target->acl_list);

	return 0;
}

void acl_del(int tid, char *address)
{
	struct target *target;
	struct acl_entry *acl, *tmp;

	target = target_lookup(tid);
	if (!target)
		return;

	list_for_each_entry_safe(acl, tmp, &target->acl_list, aclent_list) {
		if (!strcmp(address, acl->address)) {
			list_del(&acl->aclent_list);
			free(acl->address);
			free(acl);
			break;
		}
	}
}

char *acl_get(int tid, int idx)
{
	int i = 0;
	struct target *target;
	struct acl_entry *acl;

	target = target_lookup(tid);
	if (!target)
		return NULL;

	list_for_each_entry(acl, &target->acl_list, aclent_list) {
		if (idx == i++)
			return acl->address;
	}

	return NULL;
}

int tgt_target_bind(int tid, int host_no, int lid)
{
	struct target *target;

	target = target_lookup(tid);
	if (!target) {
		eprintf("target is not found %d\n", tid);
		return TGTADM_NO_TARGET;
	}

	if (hostt[host_no]) {
		eprintf("host is already binded %d %d\n", tid, host_no);
		return TGTADM_INVALID_REQUEST;
	}

	dprintf("Succeed to bind the target %d to the scsi host %d\n",
		tid, host_no);
	hostt[host_no] = target;
	return 0;
}

static struct {
	enum scsi_target_iotype value;
	char *name;
} target_iotype[] = {
	{SCSI_TARGET_FILEIO, "file"},
	{SCSI_TARGET_RAWIO, "raw"},
};

static char *target_iotype_name(enum scsi_target_state state)
{
	int i;
	char *name = NULL;

	for (i = 0; i < ARRAY_SIZE(target_iotype); i++) {
		if (target_iotype[i].value == state) {
			name = target_iotype[i].name;
			break;
		}
	}
	return name;
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

static char *target_state_name(enum scsi_target_state state)
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
	int i, err = TGTADM_INVALID_REQUEST;
	struct target *target;

	target = target_lookup(tid);
	if (!target)
		return TGTADM_NO_TARGET;

	for (i = 0; i < ARRAY_SIZE(target_state); i++) {
		if (!strcmp(target_state[i].name, str)) {
			target->target_state = target_state[i].value;
			err = 0;
			break;
		}
	}

	return err;
}

static char *print_disksize(uint64_t size)
{
	static char buf[64];
	char *format[] = {"", "K", "M", "G", "T"};
	int i;

	memset(buf, 0, sizeof(buf));
	for (i = 1; size >= (1ULL << (i * 10)) && i < ARRAY_SIZE(format); i++)
		;
	i--;
	sprintf(buf, "%" PRIu64 "%s", size >> (i * 10), format[i]);
	return buf;
}

#define TAB1 "    "
#define TAB2 TAB1 TAB1
#define TAB3 TAB1 TAB1 TAB1

int tgt_target_show_all(char *buf, int rest)
{
	int total = 0, max = rest;
	struct target *target;
	struct tgt_device *device;
	struct acl_entry *acl;
	struct it_nexus *nexus;

	list_for_each_entry(target, &target_list, t_list) {
		shprintf(total, buf, rest,
			 "Target %d: %s\n"
			 TAB1 "System information:\n"
			 TAB2 "Driver: %s\n"
			 TAB2 "Status: %s\n",
			 target->tid,
			 target->name,
			 tgt_drivers[target->lid]->name,
			 target_state_name(target->target_state));

		/* FIXME: brain-dead... */

		if (!strcmp(tgt_drivers[target->lid]->name, "iscsi"))
			shprintf(total, buf, rest, TAB1
				 "Session information:\n");
		else
			shprintf(total, buf, rest, TAB1
				 "I_T nexus information:\n");

		list_for_each_entry(nexus, &target->it_nexus_list, nexus_siblings) {
			shprintf(total, buf, rest, TAB2 "%s: %u\n",
				 strcmp(tgt_drivers[target->lid]->name, "iscsi") ?
				 "I_T nexus" : "Session", nexus->nexus_id);
		}

		if (!strcmp(tgt_drivers[target->lid]->name, "iscsi")) {
			int i, aid;

			shprintf(total, buf, rest, TAB1
				 "Account information:\n");
			for (i = 0; i < target->account.nr_inaccount; i++) {
				aid = target->account.in_aids[i];
				shprintf(total, buf, rest, TAB2 "%s\n",
					 __account_lookup_id(aid)->user);
			}
			if (target->account.out_aid) {
				aid = target->account.out_aid;
				shprintf(total, buf, rest,
					 TAB2 "%s (outgoing)\n",
					 __account_lookup_id(aid)->user);
			}
		}

		shprintf(total, buf, rest, TAB1 "ACL information:\n");
		list_for_each_entry(acl, &target->acl_list, aclent_list)
			shprintf(total, buf, rest, TAB2 "%s\n", acl->address);

		shprintf(total, buf, rest, TAB1 "LUN information:\n");
		list_for_each_entry(device, &target->device_list, device_siblings)
			shprintf(total, buf, rest,
				 TAB2 "LUN: %" PRIu64 "\n"
				 TAB3 "SCSI ID: %s\n"
				 TAB3 "SCSI SN: %s\n"
				 TAB3 "Size: %s\n"
				 TAB3 "Backing store: %s\n"
				 TAB3 "Backing store type: %s\n",
				 device->lun,
				 device->scsi_id,
				 device->scsi_sn,
				 print_disksize(device->size),
				 device->path,
				 target_iotype_name(target->target_iotype));
	}
	return total;
overflow:
	return max;
}

char *tgt_targetname(int tid)
{
	struct target *target;

	target = target_lookup(tid);
	if (!target)
		return NULL;

	return target->name;
}

#define DEFAULT_NR_ACCOUNT 16

int tgt_target_create(int lld, int tid, char *args, int t_type, int bs_type)
{
	int i;
	struct target *target, *pos;
	char *p, *q, *targetname = NULL;

	p = args;
	while ((q = strsep(&p, ","))) {
		char *str;

		str = strchr(q, '=');
		if (str) {
			*str++ = '\0';

			if (!strcmp("targetname", q))
				targetname = str;
			else
				eprintf("Unknow option %s\n", q);
		}
	};

	if (!targetname)
		return TGTADM_INVALID_REQUEST;

	target = target_lookup(tid);
	if (target) {
		eprintf("Target id %d already exists\n", tid);
		return TGTADM_TARGET_EXIST;
	}

	target = zalloc(sizeof(*target));
	if (!target)
		return TGTADM_NOMEM;

	target->name = strdup(targetname);
	if (!target->name) {
		free(target);
		return TGTADM_NOMEM;
	}

	target->account.in_aids = zalloc(DEFAULT_NR_ACCOUNT * sizeof(int));
	if (!target->account.in_aids) {
		free(target->name);
		free(target);
		return TGTADM_NOMEM;
	}
	target->account.max_inaccount = DEFAULT_NR_ACCOUNT;

	target->tid = tid;
	for (i = 0; i < ARRAY_SIZE(target->cmd_hash_list); i++)
		INIT_LIST_HEAD(&target->cmd_hash_list[i]);

	INIT_LIST_HEAD(&target->device_list);

	/* FIXME */
	if (bs_type == LU_BS_RAW) {
		target->target_iotype = SCSI_TARGET_RAWIO;
		target->bdt = &sg_bdt;
	} else {
		target->target_iotype = SCSI_TARGET_FILEIO;
		target->bdt = tgt_drivers[lld]->default_bdt;
	}

	target->target_state = SCSI_TARGET_RUNNING;
	target->lid = lld;

	tgt_cmd_queue_init(&target->cmd_queue);
	target_hlist_insert(target);

	list_for_each_entry(pos, &target_list, t_list) {
		if (target->tid < pos->tid)
			break;
	}
	list_add_tail(&target->t_list, &pos->t_list);

	INIT_LIST_HEAD(&target->acl_list);

	INIT_LIST_HEAD(&target->it_nexus_list);

	dprintf("Succeed to create a new target %d\n", tid);

	return 0;
}

int tgt_target_destroy(int tid)
{
	struct target *target;
	struct acl_entry *acl, *tmp;

	target = target_lookup(tid);
	if (!target)
		return TGTADM_NO_TARGET;

	if (!list_empty(&target->device_list)) {
		eprintf("target %d still has devices\n", tid);
		return TGTADM_TARGET_ACTIVE;
	}

	if (!list_empty(&target->cmd_queue.queue))
		return TGTADM_TARGET_ACTIVE;

	target_hlist_remove(target);
	list_del(&target->t_list);

	list_for_each_entry_safe(acl, tmp, &target->acl_list, aclent_list) {
		list_del(&acl->aclent_list);
		free(acl->address);
		free(acl);
	}

	free(target->account.in_aids);

	free(target);

	return 0;
}

int account_show(char *buf, int rest)
{
	int total = 0, max = rest;
	struct account_entry *ac;

	if (!list_empty(&accounts_list))
		shprintf(total, buf, rest, "Account list:\n");

	list_for_each_entry(ac, &accounts_list, ac_list)
		shprintf(total, buf, rest, TAB1 "%s\n", ac->user);

	return total;
overflow:
	return max;
}

__attribute__((constructor)) static void target_init(void)
{
	int i;
	for (i = 0; i < ARRAY_SIZE(target_hash_list); i++)
		INIT_LIST_HEAD(&target_hash_list[i]);
}
