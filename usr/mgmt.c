/*
 * Generic management functions
 *
 * (C) 2005 FUJITA Tomonori <tomof@acm.org>
 * (C) 2005 Mike Christie <michaelc@cs.wisc.edu>
 * This code is licenced under the GPL.
 */

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <linux/types.h>
#include <linux/netlink.h>

#include <tgt_if.h>
#include "tgtd.h"
#include "dl.h"
#include "log.h"
#include "tgtadm.h"
#include "tgt_sysfs.h"

#ifndef O_LARGEFILE
#define O_LARGEFILE	0100000
#endif

static void nlmsg_init(struct nlmsghdr *nlh, uint32_t seq,
		       uint16_t type, uint32_t len, uint16_t flags)
{
	nlh->nlmsg_pid = getpid();
	nlh->nlmsg_len = len;
	nlh->nlmsg_flags = 0;
	nlh->nlmsg_type = type;
	nlh->nlmsg_seq = seq;
}

typedef void (init_tgt_event_t) (struct tgt_event *ev, struct tgtadm_req *req);

int tgt_event_execute(struct tgtadm_req *req, int event, init_tgt_event_t *func)
{
	int err;
	struct tgt_event *ev;
	struct nlmsghdr *nlh;
	char nlm_sev[NLMSG_SPACE(sizeof(struct tgt_event))];
	char nlm_rev[NLMSG_SPACE(sizeof(struct tgt_event))];

	memset(nlm_sev, 0, sizeof(nlm_sev));
	memset(nlm_rev, 0, sizeof(nlm_rev));

	nlh = (struct nlmsghdr *) nlm_sev;

	nlmsg_init(nlh, 0, event, NLMSG_SPACE(sizeof(*ev)), 0);
	ev = NLMSG_DATA(nlh);
	func(ev, req);

	err = nl_cmd_call(nl_fd, nlh->nlmsg_type, (char *) nlh,
			  nlh->nlmsg_len, nlm_rev, sizeof(nlm_rev));
	if (err < 0)
		eprintf("%d\n", err);
	else
		err = ((struct tgt_event *) NLMSG_DATA(nlm_rev))->k.event_res.err;

	return err;
}

static void __ktarget_create(struct tgt_event *ev, struct tgtadm_req *req)
{
	sprintf(ev->u.c_target.type, "%s", typeid_to_name(dlinfo, req->typeid));
	ev->u.c_target.pid = req->pid;
}

int ktarget_create(int typeid)
{
	struct tgtadm_req req;
	int fd, err;

	req.typeid = typeid;
	req.pid = target_thread_create(&fd);
	err = tgt_event_execute(&req, TGT_UEVENT_TARGET_CREATE,
				__ktarget_create);
	if (err >= 0) {
		dprintf("%d %d\n", err, fd);

		/* FIXME */
		if (err > POLLS_PER_DRV)
			eprintf("too large tid %d\n", err);
		else {
			poll_array[POLLS_PER_DRV + err].fd = fd;
			poll_array[POLLS_PER_DRV + err].events = POLLIN;
		}
	}

	return err;
}

static void __ktarget_destroy(struct tgt_event *ev, struct tgtadm_req *req)
{
	ev->u.d_target.tid = req->tid;
}

int ktarget_destroy(int tid)
{
	struct tgtadm_req req;
	req.tid = tid;

	return tgt_event_execute(&req, TGT_UEVENT_TARGET_DESTROY,
				 __ktarget_destroy);
}

static void kdevice_create_parser(char *args, char **path, char **devtype)
{
	char *p, *q;

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
			*path = q;
		else if (!strcmp(p, "Type"))
			*devtype = q;
	}
}

static int kdevice_create(int tid, uint64_t devid, char *path)
{
	int fd, err;

	dprintf("%d %" PRIu64 " %s\n", tid, devid, path);

	fd = open(path, O_RDWR | O_LARGEFILE);
	if (fd < 0) {
		eprintf("Could not open %s errno %d\n", path, errno);
		return -errno;
	}

	err = tgt_device_create(tid, devid, fd);
	if (err < 0)
		close(fd);

	return err;
}

static int kdevice_destroy(int tid, uint64_t devid)
{
	int fd, err;
	char path[PATH_MAX], buf[PATH_MAX];

	dprintf("%u %" PRIu64 "\n", tid, devid);

	snprintf(path, sizeof(path),
		 TGT_DEVICE_SYSFSDIR "/device%d:%" PRIu64 "/fd", tid, devid);
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		eprintf("%s %d\n", path, errno);
		return -errno;
	}

	err = read(fd, buf, sizeof(buf));
	close(fd);
	if (err < 0) {
		eprintf("%d\n", err);
		return err;
	}
	sscanf(buf, "%d\n", &fd);

	err = tgt_device_destroy(tid, devid);

	if (!err)
		close(fd);

	return err;
}

static int target_mgmt(struct tgtadm_req *req, char *params, char *rbuf, int *rlen)
{
	int err = -EINVAL;

	switch (req->op) {
	case OP_NEW:
		err = ktarget_create(req->typeid);
		break;
	case OP_DELETE:
		err = ktarget_destroy(req->tid);
		break;
	default:
		break;
	}

	return err;
}

static int device_mgmt(struct tgtadm_req *req, char *params, char *rbuf, int *rlen)
{
	int err = -EINVAL;
	char *path, *devtype;

	switch (req->op) {
	case OP_NEW:
		path = devtype = NULL;
		kdevice_create_parser(params, &path, &devtype);
		if (!path)
			eprintf("Invalid path\n");
		else
			err = kdevice_create(req->tid, req->lun, path);
		break;
	case OP_DELETE:
		err = kdevice_destroy(req->tid, req->lun);
		break;
	default:
		break;
	}

	return err;
}

int tgt_mgmt(char *sbuf, char *rbuf)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *) sbuf;
	struct tgtadm_req *req;
	struct tgtadm_res *res;
	int err = -EINVAL, rlen = 0;
	char *params;

	req = NLMSG_DATA(nlh);
	params = (char *) req + sizeof(*req);

	eprintf("%d %d %d %d %d %" PRIx64 " %" PRIx64 " %s %d\n", nlh->nlmsg_len,
		req->typeid, req->mode, req->op, req->tid, req->sid, req->lun,
		params, getpid());

	switch (req->mode) {
	case MODE_TARGET:
		err = target_mgmt(req, params, rbuf, &rlen);
		break;
	case MODE_DEVICE:
		err = device_mgmt(req, params, rbuf, &rlen);
		break;
	default:
		break;
	}

	nlh = (struct nlmsghdr *) rbuf;
	nlh->nlmsg_len = NLMSG_LENGTH(sizeof(*res) + rlen);
	res = NLMSG_DATA(nlh);
	res->err = err;

	return err;
}
