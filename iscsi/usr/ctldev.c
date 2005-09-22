/*
 * (C) 2004 - 2005 FUJITA Tomonori <tomof@acm.org>
 *
 * This code is licenced under the GPL.
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
#include <asm/fcntl.h>
#include <linux/netlink.h>

#include "iscsid.h"
#include "tgt_if.h"

/*
 * tomo:
 * netlink code is temporary until ietd will be integrated to stgtd
 */

extern int ctrl_fd;

struct session_file_operations {
	int (*target_op) (int fd, u32 tid, void *arg);
	int (*session_op) (int fd, u32 tid, u64 sid, void *arg);
	int (*connection_op) (int fd, u32 tid, u64 sid, u32 cid, void *arg);
};

/* Temporary stgt glue */

static int ipc_cmnd_execute(struct nlmsghdr *nlm_send, int len)
{
	int fd, err;
	struct sockaddr_nl addr;
	struct nlmsghdr *nlm_recv;
	struct tgt_event *ev;
	struct iet_msg *msg;

	nlm_recv = calloc(1, len);
	if (!nlm_recv)
		return -ENOMEM;

	fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_TGT);
	if (fd < 0) {
		log_error("Could not create socket %d %d\n", fd, errno);
		err = fd;
		goto free_nlm;
	}
	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;
	addr.nl_pid = 0;
	addr.nl_groups = 0;

	err = connect(fd, (struct sockaddr *) &addr, sizeof(addr));
	if (err < 0) {
		log_error("Could not connect %d %d\n", err, errno);
		goto close;
	}

	err = write(fd, nlm_send, len);
	if (err < 0) {
		log_error("sendmsg failed %d %d\n", err, errno);
		goto close;
	}

	err = read(fd, nlm_recv, len);
	if (err < 0)
		goto close;

	ev = NLMSG_DATA(nlm_recv);
	switch (nlm_recv->nlmsg_type) {
		case TGT_KEVENT_TARGET_PASSTHRU:
			msg = (struct iet_msg *)ev->data;
			memcpy(nlm_send, nlm_recv, len);
			err = msg->result;
		default:
			err = ev->k.event_res.err;
	}

close:
	if (fd >= 0)
		close(fd);
free_nlm:
	free(nlm_recv);
	return err;
}

static void nlmsg_init(struct nlmsghdr *nlh, u32 pid, u32 seq, int type,
		       int len, int flags)
{
	nlh->nlmsg_pid = pid;
	nlh->nlmsg_len = len;
	nlh->nlmsg_flags = 0;
	nlh->nlmsg_type = type;
	nlh->nlmsg_seq = seq;
}

/*
 * this will have to be redone and made generic when we move it
 */
static struct nlmsghdr *get_iet_msg(u32 tid, struct iet_msg **msg)
{
	int len;
	struct nlmsghdr *nlh;
	struct tgt_event *ev;

	len = NLMSG_SPACE(sizeof(*ev) + sizeof(struct iet_msg));
	nlh = calloc(1, len);
	if (!nlh)
		return NULL;

	nlmsg_init(nlh, getpid(), 0, TGT_UEVENT_TARGET_PASSTHRU, len, 0);
	ev = NLMSG_DATA(nlh);
	ev->u.tgt_passthru.tid = tid;
	ev->u.tgt_passthru.len = sizeof(struct iet_msg);
	*msg = (struct iet_msg *)ev->data;

	return nlh;
}


static int iscsi_conn_destroy(u32 tid, u64 sid, u32 cid)
{
	struct iet_msg *msg;
	struct nlmsghdr *nlh;
	struct conn_info *info;
	int err;

	nlh = get_iet_msg(tid, &msg);
	if (!nlh)
		return -ENOMEM;

	info = &msg->u.conn_info;
	info->tid = tid;
	info->sid = sid;
	info->cid = cid;
	msg->msg_type = IET_DEL_CONN;

	err = ipc_cmnd_execute(nlh, nlh->nlmsg_len);
	free(nlh);
	return err;
}

static int __conn_close(int fd, u32 tid, u64 sid, u32 cid, void *arg)
{
	return ki->conn_destroy(tid, sid, cid);
}

static int proc_session_parse(int fd, struct session_file_operations *ops, void *arg)
{
	FILE *f;
	char buf[8192], *p;
	u32 tid, cid;
	u64 sid;
	int err;

	if ((f = fopen(PROC_SESSION, "r")) == NULL) {
		fprintf(stderr, "Can't open %s\n", PROC_SESSION);
		return errno;
	}

	while (fgets(buf, sizeof(buf), f)) {
		p = buf;
		while (isspace((int) *p))
			p++;

		if (!strncmp(p, "tid:", 4)) {
			if (sscanf(p, "tid:%u", &tid) != 1)
				break;
			if (ops->target_op)
				if ((err = ops->target_op(fd, tid, arg)) < 0)
					goto out;

		} else if (!strncmp(p, "sid:", 4)) {
			if (sscanf(p, "sid:%" SCNu64, &sid) != 1)
				break;
			if (ops->session_op)
				if ((err = ops->session_op(fd, tid, sid, arg)) < 0)
					goto out;

		} else if (!strncmp(p, "cid:", 4)) {
			if (sscanf(p, "cid:%u", &cid) != 1)
				break;
			if (ops->connection_op)
				if ((err = ops->connection_op(fd, tid, sid, cid, arg)) < 0)
					goto out;
		}
	}

	err = 0;
out:
	fclose(f);

	return err;
}

static int session_retry (int fd, u32 tid, u64 sid, void *arg)
{
	return -EAGAIN;
}

static int conn_retry (int fd, u32 tid, u64 sid, u32 cid, void *arg)
{
	return -EAGAIN;
}

struct session_file_operations conn_close_ops = {
	.connection_op = __conn_close,
};

struct session_file_operations shutdown_wait_ops = {
	.session_op = session_retry,
	.connection_op = conn_retry,
};

int server_stop(void)
{
	DIR *dir;
	struct dirent *ent;
	int tid, err;
	int32_t lun;

	dir = opendir("/sys/class/tgt_device");
	if (!dir)
		return errno;

	while ((ent = readdir(dir))) {
		err = sscanf(ent->d_name, "device%d:%u", &tid, &lun);
		if (err == 2)
			err = cops->lunit_del(tid, lun);
	}

	closedir(dir);

	dir = opendir("/sys/class/tgt_target");
	if (!dir)
		return errno;

	while ((ent = readdir(dir))) {
		err = sscanf(ent->d_name, "target%d", &tid);
		if (err == 1)
			err = cops->target_del(tid);
	}

	closedir(dir);

	return 0;
}

struct session_conn_close_arg {
	u32 tid;
	u64 sid;
};

static int session_conn_close(int fd, u32 tid, u64 sid, u32 cid, void *opaque)
{
	struct session_conn_close_arg *arg = (struct session_conn_close_arg *) opaque;
	int err;

	if (arg->tid == tid && arg->sid == sid)
		err = ki->conn_destroy(tid, sid, cid);

	return 0;
}

struct session_file_operations session_conns_close_ops = {
	.connection_op = session_conn_close,
};

int session_conns_close(u32 tid, u64 sid)
{
	int err;
	struct session_conn_close_arg arg = {tid, sid};

	err = proc_session_parse(ctrl_fd, &session_conns_close_ops, &arg);

	return err;
}

static int iscsi_param_get(u32 tid, u64 sid, struct iscsi_param *param)
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

	msg->msg_type = IET_ISCSI_PARAM_GET;

	err = ipc_cmnd_execute(nlh, nlh->nlmsg_len);
	if (err < 0)
		log_error("Can't get session param %d %d\n", info->tid, err);
	else {
		struct tgt_event *ev;

		ev = NLMSG_DATA(nlh);
		msg = (struct iet_msg *)ev->data;
		info = &msg->u.param_info;

		for (i = 0; i < session_key_last; i++)
			param[i].val = info->session_param[i];
	}

	free(nlh);
	return err;
}

static int iscsi_param_set(u32 tid, u64 sid, int type, u32 partial, struct iscsi_param *param)
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
		fprintf(stderr, "%d %d %u %llu %d %u\n",
			err, errno, tid, sid, type, partial);
	free(nlh);
	return err;
}

static int iscsi_session_create(u32 tid, u64 sid, u32 exp_cmd_sn, u32 max_cmd_sn, char *name)
{
	struct iet_msg *msg;
	struct nlmsghdr *nlh;
	struct session_info *info;
	int err;

	nlh = get_iet_msg(tid, &msg);
	if (!nlh)
		return -ENOMEM;

	info = &msg->u.sess_info;
	info->tid = tid;
	info->sid = sid;
	info->exp_cmd_sn = exp_cmd_sn;
	info->max_cmd_sn = max_cmd_sn;
	strncpy(info->initiator_name, name, sizeof(info->initiator_name) - 1);
	msg->msg_type = IET_ADD_SESSION;

	err = ipc_cmnd_execute(nlh, nlh->nlmsg_len);
	free(nlh);
	return err;
}

static int iscsi_session_destroy(u32 tid, u64 sid)
{
	struct iet_msg *msg;
	struct nlmsghdr *nlh;
	struct session_info *info;
	int err;

	nlh = get_iet_msg(tid, &msg);
	if (!nlh)
		return -ENOMEM;

	info = &msg->u.sess_info;
	info->tid = tid;
	info->sid = sid;
	msg->msg_type = IET_DEL_SESSION;

	err = ipc_cmnd_execute(nlh, nlh->nlmsg_len);
	free(nlh);
	return err;
}

static int iscsi_conn_create(u32 tid, u64 sid, u32 cid, u32 stat_sn, u32 exp_stat_sn,
			     int fd, u32 hdigest, u32 ddigest)
{
	struct iet_msg *msg;
	struct nlmsghdr *nlh;
	struct conn_info *info;
	int err;

	nlh = get_iet_msg(tid, &msg);
	if (!nlh)
		return -ENOMEM;

	info = &msg->u.conn_info;
	info->tid = tid;
	info->sid = sid;
	info->cid = cid;
	info->stat_sn = stat_sn;
	info->exp_stat_sn = exp_stat_sn;
	info->fd = fd;
	info->header_digest = hdigest;
	info->data_digest = ddigest;
	msg->msg_type = IET_ADD_CONN;

	err = ipc_cmnd_execute(nlh, nlh->nlmsg_len);
	free(nlh);
	return err;
}

static int iscsi_target_create(u32 *tid, char *name)
{
	int err;
	char nlm_ev[8912];
	struct tgt_event *ev;
	struct nlmsghdr *nlh = (struct nlmsghdr *) nlm_ev;

	memset(nlm_ev, 0, sizeof(nlm_ev));
	nlmsg_init(nlh, getpid(), 0, TGT_UEVENT_TARGET_CREATE,
		   NLMSG_SPACE(sizeof(*ev)), 0);

	ev = NLMSG_DATA(nlh);
	sprintf(ev->u.c_target.type, "%s", "iet");
	ev->u.c_target.nr_cmnds = DEFAULT_NR_QUEUED_CMNDS;

	err = ipc_cmnd_execute(nlh, nlh->nlmsg_len);
	if (err > 0) {
		*tid = err;
		err = 0;
	}

	return err;
}

static int iscsi_target_destroy(u32 tid)
{
	int err;
	char nlm_ev[8912];
	struct tgt_event *ev;
	struct nlmsghdr *nlh = (struct nlmsghdr *) nlm_ev;

	memset(nlm_ev, 0, sizeof(nlm_ev));
	nlmsg_init(nlh, getpid(), 0, TGT_UEVENT_TARGET_DESTROY,
		   NLMSG_SPACE(sizeof(*ev)), 0);

	ev = NLMSG_DATA(nlh);
	ev->u.d_target.tid = tid;

	err = ipc_cmnd_execute(nlh, nlh->nlmsg_len);

	return err;
}

static int iscsi_lunit_create(u32 tid, u32 lun, char *args)
{
	int err, fd;
	char *p, *q, *type = NULL, *path = NULL;
	char dtype[] = "tgt_vsd";
	struct tgt_event *ev;
	struct nlmsghdr *nlh;

	fprintf(stderr, "%s %d %s\n", __FUNCTION__, __LINE__, args);

	if (isspace(*args))
		args++;
	if ((p = strchr(args, '\n')))
		*p = '\0';

	while ((p = strsep(&args, ","))) {
		if (!p)
			continue;

		if (!(q = strchr(p, '=')))
			continue;
		*q++ = '\0';

		if (!strcmp(p, "Path"))
			path = q;
		else if (!strcmp(p, "Type"))
			type = q;
	}

	if (!type)
		type = dtype;
	if (!path) {
		fprintf(stderr, "%s %d NULL path\n", __FUNCTION__, __LINE__);
		return -EINVAL;
	}

	fprintf(stderr, "%s %d %s %s %Zd %Zd\n",
		__FUNCTION__, __LINE__, type, path, strlen(path), sizeof(*ev));

	fd = open(path, O_RDWR | O_LARGEFILE);
	if (fd < 0) {
		log_error("Could not open %s errno %d\n", path, errno);
		return errno;
	}

	nlh = calloc(1, NLMSG_SPACE(sizeof(*ev)));
	if (!nlh) {
		err = -ENOMEM;
		goto close_fd;
	}
	nlmsg_init(nlh, getpid(), 0, TGT_UEVENT_DEVICE_CREATE,
		   NLMSG_SPACE(sizeof(*ev)), 0);

	ev = NLMSG_DATA(nlh);
	ev->u.c_device.tid = tid;
	ev->u.c_device.dev_id = lun;
	ev->u.c_device.fd = fd;
	strncpy(ev->u.c_device.type, type, sizeof(ev->u.c_device.type));

	err = ipc_cmnd_execute(nlh, nlh->nlmsg_len);
close_fd:
	if (err) {
		close(fd);
		free(nlh);
	}
	return err;
}

static int iscsi_lunit_destroy(u32 tid, u32 lun)
{
	int err, fd;
	char nlm_ev[8912];
	struct tgt_event *ev;
	struct nlmsghdr *nlh = (struct nlmsghdr *) nlm_ev;
	char path[PATH_MAX], buf[PATH_MAX];

	fprintf(stderr, "%s %d %d %u\n", __FUNCTION__, __LINE__, tid, lun);

	memset(nlm_ev, 0, sizeof(nlm_ev));
	nlmsg_init(nlh, getpid(), 0, TGT_UEVENT_DEVICE_DESTROY,
		   NLMSG_SPACE(sizeof(*ev)), 0);

	ev = NLMSG_DATA(nlh);
	ev->u.d_device.tid = tid;
	ev->u.d_device.dev_id = lun;

	sprintf(path, "/sys/class/tgt_device/device%d:%d/fd", tid, lun);
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		perror("iscsi_lunit_destroy could not open fd file");
		return errno;
	}

	err = read(fd, buf, sizeof(buf));
	close(fd);
	if (err < 0) {
		perror("iscsi_lunit_destroy could not read fd file");
		return errno;
	}
	sscanf(buf, "%d\n", &fd);

	err = ipc_cmnd_execute(nlh, nlh->nlmsg_len);
	close(fd);
	return err;
}

struct iscsi_kernel_interface ioctl_ki = {
	.lunit_create = iscsi_lunit_create,
	.lunit_destroy = iscsi_lunit_destroy,
	.param_get = iscsi_param_get,
	.param_set = iscsi_param_set,
	.target_create = iscsi_target_create,
	.target_destroy = iscsi_target_destroy,
	.session_create = iscsi_session_create,
	.session_destroy = iscsi_session_destroy,
	.conn_create = iscsi_conn_create,
	.conn_destroy = iscsi_conn_destroy,
};

struct iscsi_kernel_interface *ki = &ioctl_ki;
