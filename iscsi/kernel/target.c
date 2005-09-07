/*
 * Copyright (C) 2002-2003 Ardis Technolgies <roman@ardistech.com>
 *
 * Released under the terms of the GNU GPL v2.0.
 */

#include <linux/mempool.h>

#include <iscsi.h>
#include <digest.h>
#include <iscsi_dbg.h>
#include <stgt.h>
#include <stgt_device.h>
#include <stgt_target.h>

#define	MAX_NR_TARGETS	(1UL << 30)

static LIST_HEAD(target_list);
static DECLARE_MUTEX(target_list_sem);
static u32 nr_targets;

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
	.wthreads = DEFAULT_NR_WTHREADS,
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

static struct iscsi_target *__target_lookup_by_id(u32 id)
{
	struct iscsi_target *target;

	list_for_each_entry(target, &target_list, t_list) {
		if (target->tid == id)
			return target;
	}
	return NULL;
}

struct iscsi_target *target_lookup_by_id(u32 id)
{
	struct iscsi_target *target;

	down(&target_list_sem);
	target = __target_lookup_by_id(id);
	up(&target_list_sem);

	return target;
}

static int target_thread_start(struct iscsi_target *target)
{
	int err;

	if ((err = nthread_start(target)) < 0)
		return err;

	return err;
}

static void target_thread_stop(struct iscsi_target *target)
{
	nthread_stop(target);
}

static int iscsi_target_create(struct stgt_target *stt)
{
	int err = -EINVAL;
	struct iscsi_target *target =
		(struct iscsi_target *) stt->stt_data;

	memset(target, 0, sizeof(*target));

	target->stt = stt;
	memcpy(&target->sess_param, &default_session_param, sizeof(default_session_param));
	memcpy(&target->trgt_param, &default_target_param, sizeof(default_target_param));

	init_MUTEX(&target->target_sem);

	INIT_LIST_HEAD(&target->session_list);
	list_add(&target->t_list, &target_list);

	nthread_init(target);

	err = target_thread_start(target);
	if (err < 0)
		return err;

	target->tid = target->stt->tid;
	return 0;
}

int target_add(struct stgt_target *stt)
{
	int err = -EEXIST;

	down(&target_list_sem);

	if (nr_targets > MAX_NR_TARGETS) {
		err = -EBUSY;
		goto out;
	}

	if (!(err = iscsi_target_create(stt)))
		nr_targets++;
out:
	up(&target_list_sem);

	return err;
}

void target_del(struct stgt_target *stt)
{
	struct iscsi_target *target =
		(struct iscsi_target *) stt->stt_data;

	down(&target_list_sem);

	target_lock(target, 0);

	if (!list_empty(&target->session_list))
		BUG();

	list_del(&target->t_list);
	nr_targets--;

	target_unlock(target);
	up(&target_list_sem);

	target_thread_stop(target);
}

int iet_info_show(struct seq_file *seq, iet_show_info_t *func)
{
	int err;
	struct iscsi_target *target;

	if ((err = down_interruptible(&target_list_sem)) < 0)
		return err;

	list_for_each_entry(target, &target_list, t_list) {
		seq_printf(seq, "tid:%u\n", target->tid);

		if ((err = target_lock(target, 1)) < 0)
			break;

		func(seq, target);

		target_unlock(target);
	}

	up(&target_list_sem);

	return 0;
}
