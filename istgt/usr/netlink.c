/*
 * iSCSI Netlink/Linux Interface
 *
 * Copyright (C) 2004 Dmitry Yusupov, Alex Aizman
 * maintained by open-iscsi@googlegroups.com
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * See the file COPYING included with this distribution for more details.
 */

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <linux/types.h>
#include <linux/netlink.h>

#include "iscsid.h"

#define NL_BUFSIZE 4096

static struct sockaddr_nl saddr, daddr;

#if 0
extern struct qelem targets_list;
static int typeid;

void async_event(char *data)
{
	struct tgt_event *ev = (struct tgt_event *) data;
	struct iet_msg *msg = (struct iet_msg *) ev->data;
	struct session *session;

	eprintf("%u %u\n", msg->msg_type, msg->result);

	switch (msg->k.conn_state_change.state) {
	case E_CONN_CLOSE:
		if (!(session = session_find_id(msg->k.conn_state_change.tid,
						msg->k.conn_state_change.sid))) {
			eprintf("session %#" PRIx64 " not found?",
				msg->k.conn_state_change.sid);
		}

		if (!--session->conn_cnt)
			session_remove(session);
		break;
	default:
		eprintf("%u\n", msg->k.conn_state_change.state);
		break;
	}
}

static int iscsi_param_set(int tid, uint64_t sid, int type, uint32_t partial,
			   struct iscsi_param *param)
{
	struct iet_msg *msg;
	struct nlmsghdr *nlh;
	struct iscsi_param_info *info;
	int err, i;

	nlh = get_iet_msg(tid, &msg);
	if (!nlh)
		return -ENOMEM;

	info = &msg->u.param_info;
	info->tid = tid;
	info->sid = sid;
	info->param_type = type;
	info->partial = partial;

	if (type == key_session)
		for (i = 0; i < session_key_last; i++)
			info->session_param[i] = param[i].val;
	else
		for (i = 0; i < target_key_last; i++)
			info->target_param[i] = param[i].val;
	msg->msg_type = IET_ISCSI_PARAM_SET;

	err = ipc_cmnd_execute(nlh, nlh->nlmsg_len);
	if (err)
		eprintf("%d %d %u %" PRIx64 "%d %u\n",
			err, errno, tid, sid, type, partial);
	free(nlh);
	return err;
}

static int iscsi_param_partial_set(int tid, uint64_t sid, int type, int key,
				   uint32_t val)
{
	struct iscsi_param *param;
	struct iscsi_param s_param[session_key_last];
	struct iscsi_param t_param[target_key_last];

	if (type == key_session)
		param = s_param;
	else
		param = t_param;

	param[key].val = val;

	return iscsi_param_set(tid, sid, type, 1 << key, param);
}

static int trgt_mgmt_params(int tid, uint64_t sid, char *params)
{
	char *p, *q;
	uint32_t s_partial = 0, t_partial = 0;
	struct iscsi_param s_param[session_key_last];
	struct iscsi_param t_param[target_key_last];

	while ((p = strsep(&params, ",")) != NULL) {
		int idx;
		uint32_t val;
		if (!*p)
			continue;
		if (!(q = strchr(p, '=')))
			continue;
		*q++ = '\0';
		val = strtol(q, NULL, 0);

		if (!((idx = param_index_by_name(p, target_keys)) < 0)) {
			if (!param_check_val(target_keys, idx, &val))
				t_partial |= (1 << idx);
			else
				eprintf("invalid val %s, %u\n",
					target_keys[idx].name, val);
			t_param[idx].val = val;

			continue;
		}

		if (!((idx = param_index_by_name(p, session_keys)) < 0)) {
			if (!param_check_val(session_keys, idx, &val))
				s_partial |= (1 << idx);
			else
				eprintf("invalid val %s, %u\n",
					session_keys[idx].name, val);
			s_param[idx].val = val;
		}
	}

	if (t_partial && s_partial) {
		eprintf("%s", "Cannot change both at the same time\n");
		return -EINVAL;
	} else if (t_partial)
		return iscsi_param_set(tid, sid, key_target, t_partial, t_param);
	else if (s_partial)
		return iscsi_param_set(tid, sid, key_session, s_partial, s_param);
	else
		eprintf("%s", "Nothing to do\n");

	return 0;
}

static int istgt_ktarget_destroy(int tid)
{
	int err;
	struct target* target;

	if (!(target = target_find_by_id(tid)))
		return -ENOENT;

	if (target->nr_sessions)
		return -EBUSY;

	if (!list_empty(&target->sessions_list)) {
		eprintf("bug still have sessions %d\n", tid);
		exit(-1);
	}

	err = ktarget_destroy(tid);
	if (err < 0)
		return err;

	remque(&target->tlist);

	free(target);

	return 0;
}

static int istgt_ktarget_create(int typeid, char *name)
{
	struct target *target;
	int err;

	if (!name)
		return -EINVAL;

	if (!(target = malloc(sizeof(*target))))
		return -ENOMEM;

	memset(target, 0, sizeof(*target));
	memcpy(target->name, name, sizeof(target->name) - 1);

	err = ktarget_create(typeid);
	if (err < 0) {
		eprintf("can't create a target %d\n", err);
		goto out;
	}

	INIT_LIST_HEAD(&target->tlist);
	INIT_LIST_HEAD(&target->sessions_list);
	target->tid = err;
	insque(&target->tlist, &targets_list);

	return err;
out:
	free(target);
	return err;
}

static int istgt_target_mgmt(struct tgtadm_req *req, char *params, char *rbuf, int *rlen)
{
	int err = -EINVAL, tid = req->tid;

	switch (req->op) {
	case OP_NEW:
		err = istgt_ktarget_create(typeid, params);
		break;
	case OP_DELETE:
		err = istgt_ktarget_destroy(tid);
		break;
	case OP_UPDATE:
		err = trgt_mgmt_params(tid, req->sid, params);
		break;
	default:
		break;
	}

	return err;
}

static int user_mgmt(struct tgtadm_req *req, char *params, char *rbuf, int *rlen)
{
	return 0;
}

static int conn_mgmt(struct tgtadm_req *req, char *params, char *rbuf, int *rlen)
{
	return 0;
}

static int session_mgmt(struct tgtadm_req *req, char *params, char *rbuf, int *rlen)
{
	return 0;
}

int ipc_mgmt(char *sbuf, char *rbuf)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *) sbuf;
	struct tgtadm_req *req;
	struct tgtadm_res *res;
	int err = -EINVAL, rlen = 0;
	char *params;

	req = NLMSG_DATA(nlh);
	params = (char *) req + sizeof(*req);

	eprintf("%d %d %d %d %d %" PRIx64 " %" PRIx64 " %s\n", nlh->nlmsg_len,
		req->typeid, req->mode, req->op, req->tid, req->sid, req->lun, params);

	switch (req->mode) {
	case MODE_DEVICE:
	case MODE_SYSTEM:
		err = tgt_mgmt(sbuf, rbuf);
		break;
	case MODE_TARGET:
		err = istgt_target_mgmt(req, params, rbuf, &rlen);
		break;
	case MODE_SESSION:
		err = session_mgmt(req, params, rbuf, &rlen);
		break;
	case MODE_CONNECTION:
		err = conn_mgmt(req, params, rbuf, &rlen);
		break;
	case MODE_USER:
		err = user_mgmt(req, params, rbuf, &rlen);
		break;
	default:
		eprintf("Unknown mode %d\n", req->mode);
		break;
	}

	nlh = (struct nlmsghdr *) rbuf;
	nlh->nlmsg_len = NLMSG_LENGTH(rlen);
	res = NLMSG_DATA(nlh);
	res->err = err;

	return err;
}

#endif

static int __nl_read(int fd, void *data, int size, int flags)
{
	struct sockaddr_nl saddr;
	socklen_t slen = sizeof(saddr);

	memset(&saddr, 0, sizeof(saddr));
	saddr.nl_family = AF_NETLINK;
	saddr.nl_pid = getpid();
	saddr.nl_groups = 0; /* not in mcast groups */

	return recvfrom(fd, data, size, flags, (struct sockaddr *) &saddr, &slen);
}

static int nl_read(char *buf)
{
	struct nlmsghdr *nlh;
	int err;

peek_again:
	err = __nl_read(nl_fd, buf, NLMSG_LENGTH(0), MSG_PEEK);
	if (err < 0) {
		eprintf("%d\n", err);
		if (errno == EAGAIN || errno == EINTR)
			goto peek_again;
		return err;
	}

	nlh = (struct nlmsghdr *) buf;

	dprintf("%d %d %d\n", nlh->nlmsg_type, nlh->nlmsg_len, getpid());

read_again:
	err = __nl_read(nl_fd, buf, nlh->nlmsg_len, 0);
	if (err < 0) {
		eprintf("%d\n", err);
		if (errno == EAGAIN || errno == EINTR)
			goto read_again;
		return err;
	}

	return err;
}

static void nlmsg_init(struct nlmsghdr *nlh, uint32_t pid, uint16_t type,
		       uint32_t len)
{
	nlh->nlmsg_pid = pid;
	nlh->nlmsg_len = len;
	nlh->nlmsg_type = type;
}

static int __kipc_call(struct iscsi_uevent *ev, int len)
{
	struct nlmsghdr *nlh;
	char sbuf[NL_BUFSIZE];
	int err;

	len = NLMSG_SPACE(len);
	memset(sbuf, 0, NL_BUFSIZE);
	nlh = (struct nlmsghdr *) sbuf;
	nlmsg_init(nlh, getpid(), ev->type, len);
	memcpy(NLMSG_DATA(sbuf), ev, len);

	err = sendto(nl_fd, ev, len, 0, (struct sockaddr *) &daddr,
		     sizeof(daddr));
	if (err < 0) {
		eprintf("%d\n", err);
		return err;
	}

	memset(sbuf, 0, NL_BUFSIZE);
	err = nl_read(sbuf);
	if (err < 0) {
		eprintf("%d\n", err);
		return err;
	}

	memcpy(ev, NLMSG_DATA(sbuf), sizeof(*ev));

	return err;
}

static int kcreate_session(uint64_t transport_handle, uint32_t initial_cmdsn,
		uint32_t *out_sid, uint32_t *out_hostno)
{
	int rc;
	struct iscsi_uevent ev;

	memset(&ev, 0, sizeof(struct iscsi_uevent));

	ev.type = ISCSI_UEVENT_CREATE_SESSION;
	ev.transport_handle = transport_handle;
	ev.u.c_session.initial_cmdsn = initial_cmdsn;

	if ((rc = __kipc_call(&ev, sizeof(ev))) < 0) {
		return rc;
	}

	*out_hostno = ev.r.c_session_ret.host_no;
	*out_sid = ev.r.c_session_ret.sid;

	return 0;
}

static int kdestroy_session(uint64_t transport_handle, uint32_t sid)
{
	int rc;
	struct iscsi_uevent ev;

	memset(&ev, 0, sizeof(struct iscsi_uevent));

	ev.type = ISCSI_UEVENT_DESTROY_SESSION;
	ev.transport_handle = transport_handle;
	ev.u.d_session.sid = sid;

	if ((rc = __kipc_call(&ev, sizeof(ev))) < 0) {
		return rc;
	}

	return 0;
}

static int kcreate_conn(uint64_t transport_handle, uint32_t sid,
		       uint32_t cid, uint32_t *out_cid)
{
	int rc;
	struct iscsi_uevent ev;

	memset(&ev, 0, sizeof(struct iscsi_uevent));

	ev.type = ISCSI_UEVENT_CREATE_CONN;
	ev.transport_handle = transport_handle;
	ev.u.c_conn.cid = cid;
	ev.u.c_conn.sid = sid;

	if ((rc = __kipc_call(&ev, sizeof(ev))) < 0) {
		eprintf("%d\n", rc);
		return rc;
	}

	if ((int)ev.r.c_conn_ret.cid == -1)
		return -EIO;

	*out_cid = ev.r.c_conn_ret.cid;
	return 0;
}

static int kdestroy_conn(uint64_t transport_handle, uint32_t sid, uint32_t cid)
{
	int rc;
	struct iscsi_uevent ev;

	memset(&ev, 0, sizeof(struct iscsi_uevent));

	ev.type = ISCSI_UEVENT_DESTROY_CONN;
	ev.transport_handle = transport_handle;
	ev.u.d_conn.sid = sid;
	ev.u.d_conn.cid = cid;

	if ((rc = __kipc_call(&ev, sizeof(ev))) < 0) {
		eprintf("%d\n", rc);
	}

	return 0;
}

static int
kbind_conn(uint64_t transport_handle, uint32_t sid, uint32_t cid,
	   uint64_t transport_eph, int is_leading, int *retcode)
{
	int rc;
	struct iscsi_uevent ev;

	ev.type = ISCSI_UEVENT_BIND_CONN;
	ev.transport_handle = transport_handle;
	ev.u.b_conn.sid = sid;
	ev.u.b_conn.cid = cid;
	ev.u.b_conn.transport_eph = transport_eph;
	ev.u.b_conn.is_leading = is_leading;

	if ((rc = __kipc_call(&ev, sizeof(ev))) < 0) {
		return rc;
	}

	*retcode = ev.r.retcode;

	return 0;
}

static int
kstop_conn(uint64_t transport_handle, uint32_t sid, uint32_t cid, int flag)
{
	int rc;
	struct iscsi_uevent ev;

	memset(&ev, 0, sizeof(struct iscsi_uevent));

	ev.type = ISCSI_UEVENT_STOP_CONN;
	ev.transport_handle = transport_handle;
	ev.u.stop_conn.sid = sid;
	ev.u.stop_conn.cid = cid;
	ev.u.stop_conn.flag = flag;

	if ((rc = __kipc_call(&ev, sizeof(ev))) < 0) {
		return rc;
	}

	return 0;
}

static int
kstart_conn(uint64_t transport_handle, uint32_t sid, uint32_t cid,
	    int *retcode)
{
	int rc;
	struct iscsi_uevent ev;

	memset(&ev, 0, sizeof(struct iscsi_uevent));

	ev.type = ISCSI_UEVENT_START_CONN;
	ev.transport_handle = transport_handle;
	ev.u.start_conn.sid = sid;
	ev.u.start_conn.cid = cid;

	if ((rc = __kipc_call(&ev, sizeof(ev))) < 0) {
		return rc;
	}

	*retcode = ev.r.retcode;
	return 0;
}

static int
kset_param(uint64_t transport_handle, uint32_t sid, uint32_t cid,
	   enum iscsi_param param, void *value, int len, int *retcode)
{
	struct iscsi_uevent *ev;
	char setparam_buf[NL_BUFSIZE];
	int rc;

	memset(setparam_buf, 0, sizeof(setparam_buf));
	ev = (struct iscsi_uevent *) setparam_buf;
	ev->type = ISCSI_UEVENT_SET_PARAM;
	ev->transport_handle = transport_handle;
	ev->u.set_param.sid = sid;
	ev->u.set_param.cid = cid;
	ev->u.set_param.param = param;
	ev->u.set_param.len = len;
	memcpy(setparam_buf + sizeof(*ev), value, len);

	if ((rc = __kipc_call(ev, sizeof(*ev) + len)) < 0) {
		return rc;
	}

	*retcode = ev->r.retcode;

	return 0;
}

int nl_init(void)
{
	int err = 0, rsize = 256 * 1024;

	nl_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_ISCSI);
	if (nl_fd < 0) {
		eprintf("Fail to create the netlink socket %d\n", errno);
		return err;
	}

	err = setsockopt(nl_fd, SOL_SOCKET, SO_RCVBUF, &rsize, sizeof(rsize));
	if (err) {
		eprintf("fail to setsockopt %d\n", errno);
		return err;
	}

	memset(&saddr, 0, sizeof(saddr));
	saddr.nl_family = AF_NETLINK;
	saddr.nl_pid = getpid();
	saddr.nl_groups = 0; /* not in mcast groups */
	err = bind(nl_fd, (struct sockaddr *) &saddr, sizeof(saddr));
	if (err) {
		eprintf("can not bind NETLINK_ISCSI socket %d\n", errno);
		close(nl_fd);
		return err;
	}

	memset(&daddr, 0, sizeof(daddr));
	daddr.nl_family = AF_NETLINK;
	daddr.nl_pid = 0; /* kernel */
	daddr.nl_groups = 0; /* unicast */

	return err;
}

struct iscsi_kernel_interface nl_ki = {
	.create_session		= kcreate_session,
	.destroy_session	= kdestroy_session,
	.create_conn		= kcreate_conn,
	.destroy_conn		= kdestroy_conn,
	.bind_conn		= kbind_conn,
	.set_param              = kset_param,
	.start_conn             = kstart_conn,
	.stop_conn              = kstop_conn,
};

struct iscsi_kernel_interface *ki = &nl_ki;
