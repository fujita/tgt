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
#include <linux/types.h>
#include <linux/netlink.h>

#include "iscsid.h"
#include "tgtd.h"
#include "tgt_if.h"
#include "tgtadm.h"
#include "tgt_sysfs.h"

extern struct qelem targets_list;
static int typeid;

static int ipc_cmnd_execute(struct nlmsghdr *nlm_send, int len)
{
	int err;
	char rbuf[8192];
	struct nlmsghdr *nlm_recv;
	struct tgt_event *ev;
	struct iet_msg *msg;

	err = nl_cmd_call(nl_fd, nlm_send->nlmsg_type,
			  (char *) nlm_send, len, rbuf, sizeof(rbuf));

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

static int filter(const struct dirent *dir)
{
	return strcmp(dir->d_name, ".") && strcmp(dir->d_name, "..");
}

static int driver_to_typeid(char *name)
{
	int i, nr, err, fd, id = -ENOENT;
	char *p, path[PATH_MAX], buf[PATH_MAX];
	struct dirent **namelist;

	nr = scandir(TGT_TYPE_SYSFSDIR, &namelist, filter, alphasort);
	for (i = 0; i < nr; i++) {
		snprintf(path, sizeof(path), TGT_TYPE_SYSFSDIR "/%s/name",
			 namelist[i]->d_name);

		fd = open(path, O_RDONLY);
		if (fd < 0) {
			eprintf("%s %d\n", path, errno);
			continue;
		}

		err = read(fd, buf, sizeof(buf));
		close(fd);
		if (err < 0) {
			eprintf("%s %d\n", path, err);
			continue;
		}

		if (strncmp(name, buf, strlen(name)))
			continue;

		for (p = namelist[i]->d_name; !isdigit((int) *p); p++)
			;
		id = atoi(p);
		break;
	}

	for (i = 0; i < nr; i++)
		free(namelist[i]);
	free(namelist);

	return id;
}

void initial_device_create(int tid, int64_t lun, char *params)
{
	char *path, *devtype;
	char d[] = "tgt_vsd";

	path = devtype = NULL;
	kdevice_create_parser(params, &path, &devtype);
	kdevice_create(tid, lun, path, devtype ? : d);
}

void initial_config_load(void)
{
	FILE *config;
	char buf[BUFSIZE];
	char *p, *q;
	int idx, tid;
	uint32_t val;

	typeid = driver_to_typeid(THIS_NAME);

	dprintf("%d\n", typeid);

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
			dprintf("creaing target %s\n", p);
			tid = istgt_ktarget_create(typeid, p);
		} else if (!strcasecmp(p, "Alias") && tid >= 0) {
			;
		} else if (!strcasecmp(p, "MaxSessions") && tid >= 0) {
			/* target->max_sessions = strtol(q, &q, 0); */
		} else if (!strcasecmp(p, "Lun") && tid >= 0) {
			uint64_t lun = strtoull(q, &q, 10);
			initial_device_create(tid, lun, q);
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
	.param_get = iscsi_param_get,
	.param_set = iscsi_param_set,
	.session_create = iscsi_session_create,
	.session_destroy = iscsi_session_destroy,
	.conn_create = iscsi_conn_create,
	.conn_destroy = iscsi_conn_destroy,
};

struct iscsi_kernel_interface *ki = &ioctl_ki;
