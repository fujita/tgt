/*
 * Copyright (C) 2002-2003 Ardis Technolgies <roman@ardistech.com>
 *
 * Released under the terms of the GNU GPL v2.0.
 */

#include <linux/mempool.h>

#include <iscsi.h>

struct iscsi_session *session_lookup(struct iscsi_target *target, uint64_t sid)
{
	struct iscsi_session *session;

	list_for_each_entry(session, &target->session_list, list) {
		if (session->sid == sid)
			return session;
	}
	return NULL;
}

int session_add(struct iscsi_target *target, struct session_info *info)
{
	struct iscsi_session *session;
	int i;

	dprintk("%p %u %" PRIx64 "\n", target, target->tid, info->sid);

	session = session_lookup(target, info->sid);
	if (session)
		return -EEXIST;

	session = kzalloc(sizeof(*session), GFP_KERNEL);
	if (!session)
		return -ENOMEM;

	session->target = target;
	session->sid = info->sid;
	memcpy(&session->param, &target->sess_param, sizeof(session->param));
	session->max_queued_cmnds = target->trgt_param.queued_cmnds;

	session->exp_cmd_sn = info->exp_cmd_sn;
	session->max_cmd_sn = info->max_cmd_sn;

	INIT_LIST_HEAD(&session->conn_list);
	INIT_LIST_HEAD(&session->pending_list);

	spin_lock_init(&session->cmnd_hash_lock);
	for (i = 0; i < ARRAY_SIZE(session->cmnd_hash); i++)
		INIT_LIST_HEAD(&session->cmnd_hash[i]);

	session->next_ttt = 1;

	list_add(&session->list, &target->session_list);

	session->ts = tgt_session_create(target->tt, NULL, NULL);

	return 0;
}

int session_del(struct iscsi_target *target, uint64_t sid)
{
	int i;
	struct iscsi_session *session;

	session = session_lookup(target, sid);
	if (!session)
		return -ENOENT;

	dprintk("%" PRIx64 "\n", session->sid);

	if (!list_empty(&session->conn_list)) {
		eprintk("%" PRIx64 " still have connections\n", session->sid);
		return -EBUSY;
	}

	BUG_ON(!list_empty(&session->conn_list));

	for (i = 0; i < ARRAY_SIZE(session->cmnd_hash); i++)
		BUG_ON(!list_empty(&session->cmnd_hash[i]));

	list_del(&session->list);

	tgt_session_destroy(session->ts, NULL, NULL);
	kfree(session);

	return 0;
}
