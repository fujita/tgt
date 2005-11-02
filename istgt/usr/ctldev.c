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
#include <fcntl.h>
#include <linux/netlink.h>

#include "iscsid.h"
#include "tgt_if.h"
#include "tgtadm.h"

#ifndef O_LARGEFILE
#define O_LARGEFILE	0100000
#endif

extern int nl_fd;
extern int nl_cmd_call(int fd, int type, char *data, int size, char *rbuf);

static int ipc_cmnd_execute(struct nlmsghdr *nlm_send, int len)
{
	int err;
	char rbuf[8192];
	struct nlmsghdr *nlm_recv;
	struct tgt_event *ev;
	struct iet_msg *msg;

	err = nl_cmd_call(nl_fd, nlm_send->nlmsg_type,
			  (char *) nlm_send, len, rbuf);

	nlm_recv = (struct nlmsghdr *) rbuf;
	ev = NLMSG_DATA(nlm_recv);
	switch (nlm_recv->nlmsg_type) {
		case TGT_KEVENT_TARGET_PASSTHRU:
			msg = (struct iet_msg *)ev->data;
			memcpy(nlm_send, nlm_recv, len);
			err = msg->result;
		default:
			err = ev->k.event_res.err;
	}

	return err;
}

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

static void nlmsg_init(struct nlmsghdr *nlh, uint32_t pid, uint32_t seq,
		       uint16_t type, uint32_t len, uint16_t flags)
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
static struct nlmsghdr *get_iet_msg(int tid, struct iet_msg **msg)
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


static int iscsi_conn_destroy(int tid, uint64_t sid, uint32_t cid)
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

static int iscsi_param_get(int tid, uint64_t sid, struct iscsi_param *param)
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

static int iscsi_session_create(int tid, uint64_t sid,
				uint32_t exp_cmd_sn, uint32_t max_cmd_sn)
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
	msg->msg_type = IET_ADD_SESSION;

	err = ipc_cmnd_execute(nlh, nlh->nlmsg_len);
	free(nlh);
	return err;
}

static int iscsi_session_destroy(int tid, uint64_t sid)
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

static int iscsi_conn_create(int tid, uint64_t sid, uint32_t cid,
			     uint32_t stat_sn, uint32_t exp_stat_sn,
			     int fd, uint32_t hdigest, uint32_t ddigest)
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

static int iscsi_target_create(int *tid)
{
	int err;
	char nlm_ev[8912];
	struct tgt_event *ev;
	struct nlmsghdr *nlh = (struct nlmsghdr *) nlm_ev;

	memset(nlm_ev, 0, sizeof(nlm_ev));
	nlmsg_init(nlh, getpid(), 0, TGT_UEVENT_TARGET_CREATE,
		   NLMSG_SPACE(sizeof(*ev)), 0);

	ev = NLMSG_DATA(nlh);
	sprintf(ev->u.c_target.type, "%s", THIS_NAME);
	ev->u.c_target.nr_cmds = DEFAULT_NR_QUEUED_CMNDS;

	err = ipc_cmnd_execute(nlh, nlh->nlmsg_len);
	if (err > 0) {
		*tid = err;
		err = 0;
	}

	return err;
}

static int iscsi_target_destroy(int tid)
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

static int iscsi_lunit_create(int tid, uint64_t lun, char *args)
{
	int err, fd;
	char *p, *q, *type = NULL, *path = NULL;
	char dtype[] = "tgt_vsd";
	struct tgt_event *ev;
	struct nlmsghdr *nlh;

	dprintf("%s\n", args);

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
		eprintf("%d %" PRIu64 "\n", tid, lun);
		return -EINVAL;
	}

	dprintf("%s %s %Zd\n", type, path, strlen(path));

	fd = open(path, O_RDWR | O_LARGEFILE);
	if (fd < 0) {
		eprintf("Could not open %s errno %d\n", path, errno);
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

static int iscsi_lunit_destroy(int tid, uint64_t lun)
{
	int err, fd;
	char nlm_ev[8912];
	struct tgt_event *ev;
	struct nlmsghdr *nlh = (struct nlmsghdr *) nlm_ev;
	char path[PATH_MAX], buf[PATH_MAX];

	dprintf("%d %" PRIu64 "\n",tid, lun);

	memset(nlm_ev, 0, sizeof(nlm_ev));
	nlmsg_init(nlh, getpid(), 0, TGT_UEVENT_DEVICE_DESTROY,
		   NLMSG_SPACE(sizeof(*ev)), 0);

	ev = NLMSG_DATA(nlh);
	ev->u.d_device.tid = tid;
	ev->u.d_device.dev_id = lun;

	sprintf(path, "/sys/class/tgt_device/device%d:%" PRIu64 "/fd",
		tid, lun);
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

static int target_mgmt(struct tgtadm_req *req, char *params, char *rbuf, int *rlen)
{
	int err = -EINVAL, tid = req->tid;

	switch (req->op) {
	case OP_NEW:
		err = target_add(&tid, params);
		break;
	case OP_DELETE:
		err = target_del(tid);
		break;
	case OP_UPDATE:
		err = trgt_mgmt_params(tid, req->sid, params);
		break;
	default:
		break;
	}

	return err;
}

static int device_mgmt(struct tgtadm_req *req, char *params, char *rbuf, int *rlen)
{
	int err = -EINVAL;

	switch (req->op) {
	case OP_NEW:
		err = iscsi_lunit_create(req->tid, req->lun, params);
		break;
	case OP_DELETE:
		err = iscsi_lunit_destroy(req->tid, req->lun);
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

static int filter(const struct dirent *dir)
{
	return strcmp(dir->d_name, ".") && strcmp(dir->d_name, "..");
}

static void all_devices_destroy(int tid)
{
	struct dirent **namelist;
	char *p;
	int i, nr;
	uint32_t lun;

	nr = scandir("/sys/class/tgt_device", &namelist, filter, alphasort);
	if (!nr)
		return;

	for (i = 0; i < nr; i++) {
		for (p = namelist[i]->d_name; !isdigit((int) *p); p++)
			;
		eprintf("%d\n", atoi(p));
		if (tid != atoi(p))
			continue;
		p = strchr(p, ':');
		if (!p)
			continue;
		lun = strtoul(++p, NULL, 10);
		iscsi_lunit_destroy(tid, lun);
	}

	for (i = 0; i < nr; i++)
		free(namelist[i]);
	free(namelist);
}

static int get_typeid(void)
{
	int err = -EINVAL, i, nr, fd, typeid = -EINVAL;
	struct dirent **namelist;
	char path[PATH_MAX], buf[PATH_MAX], *p;

	nr = scandir("/sys/class/tgt_type", &namelist, filter, alphasort);
	if (!nr)
		return -ENOENT;

	for (i = 0; i < nr; i++) {
		memset(path, 0, sizeof(path));
		strncpy(path, "/sys/class/tgt_type/", sizeof(path));
		strncat(&path[strlen(path)], namelist[i]->d_name, sizeof(path));
		strncat(&path[strlen(path)], "/name", sizeof(path));
		eprintf("%s\n", path);
		fd = open(path, O_RDONLY);
		if (fd < 0)
			continue;
		err = read(fd, buf, sizeof(buf));
		close(fd);
		if (err < 0)
			continue;
		eprintf("%s\n", buf);
		if (!strncmp(buf, THIS_NAME, strlen(THIS_NAME))) {
			for (p = namelist[i]->d_name; !isdigit((int) *p); p++)
				;
			typeid = atoi(p);
		}
	}

	for (i = 0; i < nr; i++)
		free(namelist[i]);
	free(namelist);

	return typeid;
}

static int system_mgmt(struct tgtadm_req *req, char *params, char *rbuf, int *rlen)
{
	int err = -EINVAL, i, nr, fd, typeid;
	struct dirent **namelist;
	char path[PATH_MAX], buf[PATH_MAX], *p;

	if (req->op != OP_DELETE)
		return err;

	typeid = get_typeid();

	nr = scandir("/sys/class/tgt_target", &namelist, filter, alphasort);
	if (!nr)
		return -ENOENT;

	for (i = 0; i < nr; i++) {
		memset(path, 0, sizeof(path));
		strncpy(path, "/sys/class/tgt_target/", sizeof(path));
		strncat(&path[strlen(path)], namelist[i]->d_name, sizeof(path));
		strncat(&path[strlen(path)], "/typeid", sizeof(path));
		eprintf("%s\n", path);
		fd = open(path, O_RDONLY);
		if (fd < 0)
			continue;
		err = read(fd, buf, sizeof(buf));
		close(fd);
		if (err < 0)
			continue;
		eprintf("%s\n", buf);
		if (typeid == atoi(buf)) {
			int tid;

			for (p = namelist[i]->d_name; !isdigit((int) *p); p++)
				;
			tid = atoi(p);
			all_devices_destroy(tid);
			target_del(tid);
		}
	}

	for (i = 0; i < nr; i++)
		free(namelist[i]);
	free(namelist);

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

	eprintf("%d %d %d %d %" PRIx64 " %" PRIx64 " %s\n", nlh->nlmsg_len,
		req->set, req->op, req->tid, req->sid, req->lun, params);

	if (req->set & SET_USER)
		err = user_mgmt(req, params, rbuf, &rlen);
	else if (req->set & SET_DEVICE)
		err = device_mgmt(req, params, rbuf, &rlen);
	else if (req->set & SET_CONNECTION)
		err = conn_mgmt(req, params, rbuf, &rlen);
	else if (req->set & SET_SESSION)
		err = session_mgmt(req, params, rbuf, &rlen);
	else if (req->set & SET_TARGET)
		err = target_mgmt(req, params, rbuf, &rlen);
	else if (!req->set)
		err = system_mgmt(req, params, rbuf, &rlen);

	nlh = (struct nlmsghdr *) rbuf;
	nlh->nlmsg_len = NLMSG_LENGTH(rlen);
	res = NLMSG_DATA(nlh);
	res->err = err;

	return err;
}

/* This is temporary. */

#define CONFIG_FILE	"/etc/ietd.conf"
#define BUFSIZE	8192

/* this is the orignal Ardis code. */
static char *target_sep_string(char **pp)
{
	char *p = *pp;
	char *q;

	for (p = *pp; isspace(*p); p++)
		;
	for (q = p; *q && !isspace(*q); q++)
		;
	if (*q)
		*q++ = 0;
	else
		p = NULL;
	*pp = q;
	return p;
}

void initial_config_load(void)
{
	FILE *config;
	char buf[BUFSIZE];
	char *p, *q;
	int idx, tid;
	uint32_t val;

	eprintf("%s\n", "load config");

	if (!(config = fopen(CONFIG_FILE, "r")))
		return;

	tid = -1;
	while (fgets(buf, BUFSIZE, config)) {
		q = buf;
		p = target_sep_string(&q);
		if (!p || *p == '#')
			continue;
		if (!strcasecmp(p, "Target")) {
			tid = 0;
			if (!(p = target_sep_string(&q)))
				continue;
			eprintf("creaing target %s\n", p);
			if (target_add(&tid, p) < 0)
				tid = -1;
		} else if (!strcasecmp(p, "Alias") && tid >= 0) {
			;
		} else if (!strcasecmp(p, "MaxSessions") && tid >= 0) {
			/* target->max_sessions = strtol(q, &q, 0); */
		} else if (!strcasecmp(p, "Lun") && tid >= 0) {
			uint64_t lun = strtoull(q, &q, 10);
			eprintf("creaing lun %d %" PRIu64 " %s\n", tid, lun, p);
			iscsi_lunit_create(tid, lun, q);
		} else if (!((idx = param_index_by_name(p, target_keys)) < 0) && tid >= 0) {
			val = strtol(q, &q, 0);
			if (param_check_val(target_keys, idx, &val) < 0)
				log_warning("%s, %u\n", target_keys[idx].name, val);
			iscsi_param_partial_set(tid, 0, key_target, idx, val);
		} else if (!((idx = param_index_by_name(p, session_keys)) < 0) && tid >= 0) {
			char *str = target_sep_string(&q);
			if (param_str_to_val(session_keys, idx, str, &val) < 0)
				continue;
			if (param_check_val(session_keys, idx, &val) < 0)
				log_warning("%s, %u\n", session_keys[idx].name, val);
			iscsi_param_partial_set(tid, 0, key_session, idx, val);
		}
	}

	fclose(config);

	return;
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
