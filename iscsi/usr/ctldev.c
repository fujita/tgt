/*
 * (C) 2004 - 2005 FUJITA Tomonori <tomof@acm.org>
 *
 * This code is licenced under the GPL.
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <linux/netlink.h>

#include "iscsid.h"
#include "stgt_if.h"

#define CTL_DEVICE	"/dev/ietctl"

extern int ctrl_fd;

struct session_file_operations {
	int (*target_op) (int fd, u32 tid, void *arg);
	int (*session_op) (int fd, u32 tid, u64 sid, void *arg);
	int (*connection_op) (int fd, u32 tid, u64 sid, u32 cid, void *arg);
};

static int ctrdev_open(void)
{
	FILE *f;
	char devname[256];
	char buf[256];
	int devn;
	int ctlfd;

	if (!(f = fopen("/proc/devices", "r"))) {
		perror("Cannot open control path to the driver\n");
		return -1;
	}

	devn = 0;
	while (!feof(f)) {
		if (!fgets(buf, sizeof (buf), f)) {
			break;
		}
		if (sscanf(buf, "%d %s", &devn, devname) != 2) {
			continue;
		}
		if (!strcmp(devname, "ietctl")) {
			break;
		}
		devn = 0;
	}

	fclose(f);
	if (!devn) {
		printf
		    ("cannot find iscsictl in /proc/devices - "
		     "make sure the module is loaded\n");
		return -1;
	}

	unlink(CTL_DEVICE);
	if (mknod(CTL_DEVICE, (S_IFCHR | 0600), (devn << 8))) {
		printf("cannot create %s %d\n", CTL_DEVICE, errno);
		return -1;
	}

	ctlfd = open(CTL_DEVICE, O_RDWR);
	if (ctlfd < 0) {
		printf("cannot open %s %d\n", CTL_DEVICE, errno);
		return -1;
	}

	return ctlfd;
}

static int iscsi_target_create(u32 *tid, char *name)
{
	int err;
	struct target_info info;

	memset(&info, 0, sizeof(info));

	info.tid = *tid;
	if ((err = ioctl(ctrl_fd, ADD_TARGET, &info)) < 0)
		log_warning("can't create a target %d %u\n", errno, info.tid);

	*tid = info.tid;
	return err;
}

static int iscsi_target_destroy(u32 tid)
{
	struct target_info info;

	memset(&info, 0, sizeof(info));
	info.tid = tid;

	return ioctl(ctrl_fd, DEL_TARGET, &info);
}

static int iscsi_conn_destroy(u32 tid, u64 sid, u32 cid)
{
	int err;
	struct conn_info info;

	info.tid = tid;
	info.sid = sid;
	info.cid = cid;

	if ((err = ioctl(ctrl_fd, DEL_CONN, &info)) < 0)
		err = errno;

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

	dir = opendir("/sys/class/stgt_device");
	if (!dir)
		return errno;

	while ((ent = readdir(dir))) {
		err = sscanf(ent->d_name, "device%d:%u", &tid, &lun);
		if (err == 2)
			err = cops->lunit_del(tid, lun);
	}

	closedir(dir);

	dir = opendir("/sys/class/stgt_target");
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
	int err, i;
	struct iscsi_param_info info;

	memset(&info, 0, sizeof(info));
	info.tid = tid;
	info.sid = sid;

	if ((err = ioctl(ctrl_fd, ISCSI_PARAM_GET, &info)) < 0)
		log_error("Can't set session param %d %d\n", info.tid, errno);

	for (i = 0; i < session_key_last; i++)
		param[i].val = info.session_param[i];

	return err;
}

static int iscsi_param_set(u32 tid, u64 sid, int type, u32 partial, struct iscsi_param *param)
{
	int i, err;
	struct iscsi_param_info info;

	memset(&info, 0, sizeof(info));
	info.tid = tid;
	info.sid = sid;
	info.param_type = type;
	info.partial = partial;

	if (info.param_type == key_session)
		for (i = 0; i < session_key_last; i++)
			info.session_param[i] = param[i].val;
	else
		for (i = 0; i < target_key_last; i++)
			info.target_param[i] = param[i].val;

	if ((err = ioctl(ctrl_fd, ISCSI_PARAM_SET, &info)) < 0)
		fprintf(stderr, "%d %d %u " "%" PRIu64 " %d %u\n",
			err, errno, tid, sid, type, partial);

	return err;
}

static int iscsi_session_create(u32 tid, u64 sid, u32 exp_cmd_sn, u32 max_cmd_sn, char *name)
{
	struct session_info info;

	memset(&info, 0, sizeof(info));

	info.tid = tid;
	info.sid = sid;
	info.exp_cmd_sn = exp_cmd_sn;
	info.max_cmd_sn = max_cmd_sn;
	strncpy(info.initiator_name, name, sizeof(info.initiator_name) - 1);

	return ioctl(ctrl_fd, ADD_SESSION, &info);
}

static int iscsi_session_destroy(u32 tid, u64 sid)
{
	struct session_info info;

	memset(&info, 0, sizeof(info));

	info.tid = tid;
	info.sid = sid;

	return ioctl(ctrl_fd, DEL_SESSION, &info);
}

static int iscsi_conn_create(u32 tid, u64 sid, u32 cid, u32 stat_sn, u32 exp_stat_sn,
			     int fd, u32 hdigest, u32 ddigest)
{
	struct conn_info info;

	memset(&info, 0, sizeof(info));

	info.tid = tid;
	info.sid = sid;
	info.cid = cid;
	info.stat_sn = stat_sn;
	info.exp_stat_sn = exp_stat_sn;
	info.fd = fd;
	info.header_digest = hdigest;
	info.data_digest = ddigest;

	return ioctl(ctrl_fd, ADD_CONN, &info);
}

/* Temporary stgt glue */

static int ipc_cmnd_execute(char *data, int len)
{
	int fd, err;
	struct sockaddr_un addr;
	char nlm_ev[NLMSG_SPACE(sizeof(struct stgt_event))];
	struct stgt_event *ev;
	struct nlmsghdr *nlh = (struct nlmsghdr *) nlm_ev;

	fd = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (fd < 0)
		return fd;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_LOCAL;
	memcpy((char *) &addr.sun_path + 1, STGT_IPC_NAMESPACE,
	       strlen(STGT_IPC_NAMESPACE));

	err = connect(fd, (struct sockaddr *) &addr, sizeof(addr));
	if (err < 0)
		return err;

	err = write(fd, data, len);
	if (err < 0)
		goto out;

	err = read(fd, nlm_ev, sizeof(nlm_ev));
	if (err < 0)
		goto out;

	ev = NLMSG_DATA(nlh);
	err = ev->k.event_res.err;

out:
	if (fd > 0)
		close(fd);

	return fd;
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

static int iscsi_lunit_create(u32 tid, u32 lun, char *args)
{
	int err;
	char nlm_ev[8912], *p, *q, *type = NULL, *path = NULL;
	char dtype[] = "stgt_vsd";
	struct stgt_event *ev;
	struct nlmsghdr *nlh = (struct nlmsghdr *) nlm_ev;

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

	fprintf(stderr, "%s %d %s %s %d %d\n",
		__FUNCTION__, __LINE__, type, path, strlen(path), sizeof(*ev));

	memset(nlm_ev, 0, sizeof(nlm_ev));
	nlmsg_init(nlh, getpid(), 0, STGT_UEVENT_DEVICE_CREATE,
		   NLMSG_SPACE(sizeof(*ev) + strlen(path)), 0);

	ev = NLMSG_DATA(nlh);
	ev->u.c_device.tid = tid;
	ev->u.c_device.lun = lun;
	strncpy(ev->u.c_device.type, type, sizeof(ev->u.c_device.type));
	memcpy((char *) ev + sizeof(*ev), path, strlen(path));

	err = ipc_cmnd_execute(nlm_ev, nlh->nlmsg_len);

	return err;
}

static int iscsi_lunit_destroy(u32 tid, u32 lun)
{
	int err;
	char nlm_ev[8912];
	struct stgt_event *ev;
	struct nlmsghdr *nlh = (struct nlmsghdr *) nlm_ev;

	fprintf(stderr, "%s %d %d %u\n", __FUNCTION__, __LINE__, tid, lun);

	memset(nlm_ev, 0, sizeof(nlm_ev));
	nlmsg_init(nlh, getpid(), 0, STGT_UEVENT_DEVICE_DESTROY,
		   NLMSG_SPACE(sizeof(*ev)), 0);

	ev = NLMSG_DATA(nlh);
	ev->u.d_device.tid = tid;
	ev->u.d_device.lun = lun;

	err = ipc_cmnd_execute(nlm_ev, nlh->nlmsg_len);

	return err;
}

struct iscsi_kernel_interface ioctl_ki = {
	.ctldev_open = ctrdev_open,
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
