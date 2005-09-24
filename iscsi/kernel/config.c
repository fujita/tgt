/*
 * (C) 2004 - 2005 FUJITA Tomonori <tomof@acm.org>
 *
 * This code is licenced under the GPL.
 */

#include <linux/proc_fs.h>

#include <tgt.h>
#include <tgt_target.h>

#include "iet_u.h"
#include "iscsi.h"
#include "iscsi_dbg.h"

struct proc_entries {
	const char *name;
	struct file_operations *fops;
};

static struct proc_entries iet_proc_entries[] =
{
/* 	{"volume", &volume_seq_fops}, */
	{"session", &session_seq_fops},
};

static struct proc_dir_entry *proc_iet_dir;

void iet_procfs_exit(void)
{
	int i;

	if (!proc_iet_dir)
		return;

	for (i = 0; i < ARRAY_SIZE(iet_proc_entries); i++)
		remove_proc_entry(iet_proc_entries[i].name, proc_iet_dir);

	remove_proc_entry(proc_iet_dir->name, proc_iet_dir->parent);
}

int iet_procfs_init(void)
{
	int i;
	struct proc_dir_entry *ent;

	if (!(proc_iet_dir = proc_mkdir("net/iet", 0)))
		goto err;

	proc_iet_dir->owner = THIS_MODULE;

	for (i = 0; i < ARRAY_SIZE(iet_proc_entries); i++) {
		ent = create_proc_entry(iet_proc_entries[i].name, 0, proc_iet_dir);
		if (ent)
			ent->proc_fops = iet_proc_entries[i].fops;
		else
			goto err;
	}

	return 0;

err:
	if (proc_iet_dir)
		iet_procfs_exit();

	return -ENOMEM;
}

static int add_conn(struct iscsi_target *target, struct conn_info *info)
{
	struct iscsi_session *session;

	session = session_lookup(target, info->sid);
	if (!session)
		return -ENOENT;

	return conn_add(session, info);
}

static int del_conn(struct iscsi_target *target, struct conn_info *info)
{
	struct iscsi_session *session;

	session = session_lookup(target, info->sid);
	if (!session)
		return -ENOENT;

	return conn_del(session, info);
}

int iet_msg_recv(struct tgt_target *tgt, uint32_t len, void *data)
{
	struct iscsi_target *target = tgt->tt_data;
	struct iet_msg *msg = data;
	int err;

	err = target_lock(target, 1);
	if (err < 0) {
		eprintk("interrupted %u %d\n", err, msg->msg_type);
		goto done;
	}

	eprintk("msg_type %d\n", msg->msg_type);

	switch (msg->msg_type) {
	case IET_ADD_SESSION:
		err = session_add(target, &msg->u.sess_info);
		break;

	case IET_DEL_SESSION:
		err = session_del(target, msg->u.sess_info.sid);
		break;

	case IET_ISCSI_PARAM_SET:
		err = iscsi_param_set(target, &msg->u.param_info, 1);
		break;

	case IET_ISCSI_PARAM_GET:
		err = iscsi_param_set(target, &msg->u.param_info, 0);
		break;

	case IET_ADD_CONN:
		err = add_conn(target, &msg->u.conn_info);
		break;

	case IET_DEL_CONN:
		err = del_conn(target, &msg->u.conn_info);
		break;
	default:
		err = -EINVAL;
	}

	target_unlock(target);
done:
	msg->result = err;
	tgt_msg_send(tgt, msg, sizeof(*msg), GFP_KERNEL);
	return err;
}

int event_send(struct tgt_target *tgt, u32 tid, u64 sid, u32 cid, u32 state)
{
	struct iet_msg msg;

	msg.k.conn_state_change.tid = tid;
	msg.k.conn_state_change.sid = sid;
	msg.k.conn_state_change.cid = cid;
	msg.k.conn_state_change.state = state;

	return tgt_msg_send(tgt, &msg, sizeof(msg), GFP_ATOMIC);
}
