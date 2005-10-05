/*
 * Copyright (C) 2002-2003 Ardis Technolgies <roman@ardistech.com>
 *
 * Released under the terms of the GNU GPL v2.0.
 */

#include <linux/file.h>
#include <linux/ip.h>
#include <net/tcp.h>

#include <iscsi.h>
#include <digest.h>

static struct iscsi_conn *conn_lookup(struct iscsi_session *session, u16 cid)
{
	struct iscsi_conn *conn;

	list_for_each_entry(conn, &session->conn_list, list) {
		if (conn->cid == cid)
			return conn;
	}
	return NULL;
}

static void state_change(struct sock *sk)
{
	struct iscsi_conn *conn = sk->sk_user_data;
	struct iscsi_target *target = conn->session->target;

	if (sk->sk_state != TCP_ESTABLISHED)
		conn_close(conn);
	else
		nthread_wakeup(target);

	target->nthread_info.old_state_change(sk);
}

static void data_ready(struct sock *sk, int len)
{
	struct iscsi_conn *conn = sk->sk_user_data;
	struct iscsi_target *target = conn->session->target;

	nthread_wakeup(target);
	target->nthread_info.old_data_ready(sk, len);
}

static void socket_bind(struct iscsi_conn *conn)
{
	int opt = 1;
	mm_segment_t oldfs;
	struct iscsi_session *session = conn->session;
	struct iscsi_target *target = session->target;

	dprintk(D_GENERIC, "%llu\n", (unsigned long long) session->sid);

	conn->sock = SOCKET_I(conn->file->f_dentry->d_inode);
	conn->sock->sk->sk_user_data = conn;

	write_lock(&conn->sock->sk->sk_callback_lock);
	target->nthread_info.old_state_change = conn->sock->sk->sk_state_change;
	conn->sock->sk->sk_state_change = state_change;

	target->nthread_info.old_data_ready = conn->sock->sk->sk_data_ready;
	conn->sock->sk->sk_data_ready = data_ready;
	write_unlock(&conn->sock->sk->sk_callback_lock);

	oldfs = get_fs();
	set_fs(get_ds());
	conn->sock->ops->setsockopt(conn->sock, SOL_TCP, TCP_NODELAY,
				    (void *)&opt, sizeof(opt));
	set_fs(oldfs);
}

int conn_free(struct iscsi_conn *conn)
{
	dprintk(D_GENERIC, "%p %#Lx %u\n", conn->session,
		(unsigned long long) conn->session->sid, conn->cid);

	BUG_ON(atomic_read(&conn->nr_cmnds));
	BUG_ON(!list_empty(&conn->pdu_list));
	BUG_ON(!list_empty(&conn->write_list));

	list_del(&conn->list);
	list_del(&conn->poll_list);

	digest_cleanup(conn);
	kfree(conn);

	return 0;
}

void conn_close(struct iscsi_conn *conn)
{
	if (test_and_clear_bit(CONN_ACTIVE, &conn->state))
		set_bit(CONN_CLOSING, &conn->state);

	nthread_wakeup(conn->session->target);
}

int conn_add(struct iscsi_session *session, struct conn_info *info)
{
	struct iscsi_conn *conn;

	dprintk(D_SETUP, "%#Lx:%u\n",
		(unsigned long long) session->sid, info->cid);

	conn = conn_lookup(session, info->cid);
	if (conn)
		return -EEXIST;

	conn = kzalloc(sizeof(*conn), GFP_KERNEL);
	if (!conn)
		return -ENOMEM;

	conn->session = session;
	conn->cid = info->cid;
	conn->stat_sn = info->stat_sn;
	conn->exp_stat_sn = info->exp_stat_sn;

	conn->hdigest_type = info->header_digest;
	conn->ddigest_type = info->data_digest;
	if (digest_init(conn) < 0) {
		kfree(conn);
		return -ENOMEM;
	}

	spin_lock_init(&conn->list_lock);
	atomic_set(&conn->nr_cmnds, 0);
	atomic_set(&conn->nr_busy_cmnds, 0);
	INIT_LIST_HEAD(&conn->pdu_list);
	INIT_LIST_HEAD(&conn->write_list);
	INIT_LIST_HEAD(&conn->poll_list);

	list_add(&conn->list, &session->conn_list);

	set_bit(CONN_ACTIVE, &conn->state);

	conn->file = fget(info->fd);
	socket_bind(conn);

	list_add(&conn->poll_list, &session->target->nthread_info.active_conns);

	nthread_wakeup(conn->session->target);

	return 0;
}

int conn_del(struct iscsi_session *session, struct conn_info *info)
{
	struct iscsi_conn *conn;
	int err = -EEXIST;

	if (!(conn = conn_lookup(session, info->cid)))
		return err;

	conn_close(conn);

	return 0;
}
