/*
 * Copyright (C) 2002-2003 Ardis Technolgies <roman@ardistech.com>
 *
 * Released under the terms of the GNU GPL v2.0.
 */

#include <linux/mempool.h>

#include <iscsi.h>
#include <digest.h>
#include <iscsi_dbg.h>
#include <tgt.h>
#include <tgt_device.h>
#include <tgt_target.h>

static DECLARE_MUTEX(target_list_sem);

static struct iscsi_sess_param default_session_param = {
	.initial_r2t = 1,
	.immediate_data = 1,
	.max_connections = 1,
	.max_recv_data_length = 8192,
	.max_xmit_data_length = 8192,
	.max_burst_length = 262144,
	.first_burst_length = 65536,
	.default_wait_time = 2,
	.default_retain_time = 20,
	.max_outstanding_r2t = 1,
	.data_pdu_inorder = 1,
	.data_sequence_inorder = 1,
	.error_recovery_level = 0,
	.header_digest = DIGEST_NONE,
	.data_digest = DIGEST_NONE,
	.ofmarker = 0,
	.ifmarker = 0,
	.ofmarkint = 2048,
	.ifmarkint = 2048,
};

static struct iscsi_trgt_param default_target_param = {
	.target_type = 0,
	.queued_cmnds = DEFAULT_NR_QUEUED_CMNDS,
};

inline int target_lock(struct iscsi_target *target, int interruptible)
{
	int err = 0;

	if (interruptible)
		err = down_interruptible(&target->target_sem);
	else
		down(&target->target_sem);

	return err;
}

inline void target_unlock(struct iscsi_target *target)
{
	up(&target->target_sem);
}

int target_add(struct tgt_target *tt)
{
	int err = -EINVAL;
	struct iscsi_target *target = tt->tt_data;

	down(&target_list_sem);

	memset(target, 0, sizeof(*target));

	target->tt = tt;
	target->tid = target->tt->tid;

	memcpy(&target->sess_param, &default_session_param, sizeof(default_session_param));
	memcpy(&target->trgt_param, &default_target_param, sizeof(default_target_param));

	init_MUTEX(&target->target_sem);
	INIT_LIST_HEAD(&target->session_list);

	nthread_init(target);
	err = nthread_start(target);

	up(&target_list_sem);

	return err;
}

void target_del(struct tgt_target *tt)
{
	struct iscsi_target *target =
		(struct iscsi_target *) tt->tt_data;

	down(&target_list_sem);

	target_lock(target, 0);

	/* kernel may crash until tgt supports lifetime management. */
	BUG_ON(!list_empty(&target->session_list));

	target_unlock(target);
	up(&target_list_sem);

	nthread_stop(target);
}
