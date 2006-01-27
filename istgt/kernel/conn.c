/*
 * Copyright (C) 2002-2003 Ardis Technolgies <roman@ardistech.com>
 *
 * Released under the terms of the GNU GPL v2.0.
 */
#include <linux/file.h>
#include <linux/ip.h>
#include <net/tcp.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_transport_iscsi.h>

#include <iscsi.h>
#include <digest.h>

int conn_close(struct iscsi_conn *conn)
{
	/* TODO: pass in error */
	iscsi_conn_error(conn->cls_conn, ISCSI_ERR_CONN_FAILED);
	return 0;
}

static void state_change(struct sock *sk)
{
	struct iscsi_conn *conn = sk->sk_user_data;
	struct iscsi_session *session = conn->session;

	if (sk->sk_state != TCP_ESTABLISHED)
		conn_close(conn);
	else
		nthread_wakeup(session);

	session->nthread_info.old_state_change(sk);
}

static void data_ready(struct sock *sk, int len)
{
	struct iscsi_conn *conn = sk->sk_user_data;
	struct iscsi_session *session = conn->session;

	nthread_wakeup(session);
	session->nthread_info.old_data_ready(sk, len);
}

int
istgt_conn_bind(struct iscsi_cls_session *cls_session,
		struct iscsi_cls_conn *cls_conn, uint32_t transport_fd,
		int is_leading)
{
	struct Scsi_Host *shost = iscsi_session_to_shost(cls_session);
	struct iscsi_session *session = iscsi_hostdata(shost->hostdata);
	struct iscsi_conn *conn = cls_conn->dd_data;
	int opt = 1, err;
	mm_segment_t oldfs;

	dprintk("%llu\n", (unsigned long long) session->sid);

	conn->file = fget(transport_fd);

	conn->sock = sockfd_lookup(transport_fd, &err);
	conn->sock->sk->sk_user_data = conn;

	write_lock(&conn->sock->sk->sk_callback_lock);
	session->nthread_info.old_state_change = conn->sock->sk->sk_state_change;
	conn->sock->sk->sk_state_change = state_change;

	session->nthread_info.old_data_ready = conn->sock->sk->sk_data_ready;
	conn->sock->sk->sk_data_ready = data_ready;
	write_unlock(&conn->sock->sk->sk_callback_lock);

	oldfs = get_fs();
	set_fs(get_ds());
	conn->sock->ops->setsockopt(conn->sock, SOL_TCP, TCP_NODELAY,
				    (void *)&opt, sizeof(opt));
	set_fs(oldfs);
	return 0;
}

int conn_free(struct iscsi_conn *conn)
{
	struct completion *wait = conn->free_done;

	dprintk("%p %#Lx %u\n", conn->session,
		(unsigned long long) conn->session->sid, conn->cid);

	BUG_ON(atomic_read(&conn->nr_cmnds));
	BUG_ON(!list_empty(&conn->pdu_list));
	BUG_ON(!list_empty(&conn->write_list));

	list_del(&conn->list);
	list_del(&conn->poll_list);

	digest_cleanup(conn);

	sock_release(conn->sock);

	if (wait)
		complete(wait);

	return 0;
}

void istgt_conn_destroy(struct iscsi_cls_conn *cls_conn)
{
	struct iscsi_conn *conn = cls_conn->dd_data;
	struct iscsi_session *session = conn->session;
	DECLARE_COMPLETION(wait);

	conn->free_done = &wait;

	if (test_and_clear_bit(CONN_ACTIVE, &conn->state))
		set_bit(CONN_CLOSING, &conn->state);

	nthread_wakeup(session);
	wait_for_completion(&wait);
}

struct iscsi_cls_conn *istgt_conn_create(struct iscsi_cls_session *cls_session,
					 uint32_t cid)
{
	struct Scsi_Host *shost = iscsi_session_to_shost(cls_session);
	struct iscsi_session *session = iscsi_hostdata(shost->hostdata);
	struct iscsi_cls_conn *cls_conn;
	struct iscsi_conn *conn;

	dprintk("%#Lx:%u\n", (unsigned long long) session->sid, cid);

        cls_conn = iscsi_create_conn(cls_session, cid);
	if (!cls_conn)
		return NULL;

	conn = cls_conn->dd_data;
	memset(conn, 0, sizeof(*conn));

	conn->cls_conn = cls_conn;
	conn->session = session;
	conn->cid = cid;
//	conn->stat_sn = info->stat_sn;
// mnc	conn->exp_stat_sn = info->exp_stat_sn;

//	conn->hdigest_type = info->header_digest;
//	conn->ddigest_type = info->data_digest;
//	if (digest_init(conn) < 0) {
//		iscsi_destroy_conn(cls_conn);
//		return NULL;
//	}

	spin_lock_init(&conn->list_lock);
	atomic_set(&conn->nr_cmnds, 0);
	atomic_set(&conn->nr_busy_cmnds, 0);
	INIT_LIST_HEAD(&conn->pdu_list);
	INIT_LIST_HEAD(&conn->write_list);
	INIT_LIST_HEAD(&conn->poll_list);

	list_add(&conn->list, &session->conn_list);
	return cls_conn;
}

int istgt_conn_start(struct iscsi_cls_conn *cls_conn)
{
	struct iscsi_conn *conn = cls_conn->dd_data;
	struct iscsi_session *session = conn->session;

	set_bit(CONN_ACTIVE, &conn->state);
	list_add(&conn->poll_list, &session->nthread_info.active_conns);
	nthread_wakeup(conn->session);
	return 0;
}
