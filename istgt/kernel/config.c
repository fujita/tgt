/*
 * (C) 2004 - 2005 FUJITA Tomonori <tomof@acm.org>
 *
 * This code is licenced under the GPL.
 */

#include <iscsi.h>

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

	err = down_interruptible(&target->target_sem);
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

	up(&target->target_sem);
done:
	msg->result = err;
	tgt_msg_send(tgt, msg, sizeof(*msg), GFP_KERNEL);
	return err;
}

int event_send(struct tgt_target *tgt, uint64_t sid, uint32_t cid,
	       uint32_t state)
{
	struct iet_msg msg;

	msg.k.conn_state_change.tid = tgt->tid;
	msg.k.conn_state_change.sid = sid;
	msg.k.conn_state_change.cid = cid;
	msg.k.conn_state_change.state = state;

	return tgt_msg_send(tgt, &msg, sizeof(msg), GFP_ATOMIC);
}
