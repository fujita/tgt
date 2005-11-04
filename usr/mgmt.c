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
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
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
	sprintf(ev->u.c_target.type, "%s", typeid_to_name(req->typeid));
}

int ktarget_create(int typeid)
{
	struct tgtadm_req req;
	req.typeid = typeid;

	return tgt_event_execute(&req, TGT_UEVENT_TARGET_CREATE,
				 __ktarget_create);
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

struct kdevice_create_info {
	int fd;
	char devtype[256];
};

static void __kdevice_create(struct tgt_event *ev, struct tgtadm_req *req)
{
	struct kdevice_create_info *info =
		(struct kdevice_create_info *) ((char *) req + sizeof(*req));

	ev->u.c_device.tid = req->tid;
	ev->u.c_device.dev_id = req->lun;
	ev->u.c_device.fd = info->fd;
	strncpy(ev->u.c_device.type, info->devtype,
		sizeof(ev->u.c_device.type));
}

void kdevice_create_parser(char *args, char **path, char **devtype)
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

int kdevice_create(int tid, uint64_t devid, char *path, char *devtype)
{
	int fd;
	char buf[sizeof(struct tgtadm_req) + sizeof(struct kdevice_create_info)];
	struct tgtadm_req *req;
	struct kdevice_create_info *info;

	dprintf("%d %" PRIu64 " %s %s\n", tid, devid, path, devtype);

	req = (struct tgtadm_req *) buf;
	info = (struct kdevice_create_info *) (buf + sizeof(*req));

	req->tid = tid;
	req->lun = devid;

	fd = open(path, O_RDWR | O_LARGEFILE);
	if (fd < 0) {
		eprintf("Could not open %s errno %d\n", path, errno);
		return -errno;
	}
	info->fd = fd;
	strncpy(info->devtype, devtype, sizeof(info->devtype));

	return tgt_event_execute(req, TGT_UEVENT_DEVICE_CREATE,
				 __kdevice_create);
}

static void __kdevice_destroy(struct tgt_event *ev, struct tgtadm_req *req)
{
	ev->u.d_device.tid = req->tid;
	ev->u.d_device.dev_id = req->lun;
}

int kdevice_destroy(int tid, uint64_t devid)
{
	int fd, err;
	struct tgtadm_req req;
	char path[PATH_MAX], buf[PATH_MAX];

	req.tid = tid;
	req.lun = devid;

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

	err = tgt_event_execute(&req, TGT_UEVENT_DEVICE_DESTROY,
				__kdevice_destroy);
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
		if (!path || !devtype)
			eprintf("Invalid path or device type\n");
		else
			err = kdevice_create(req->tid, req->lun, path,devtype);
		break;
	case OP_DELETE:
		err = kdevice_destroy(req->tid, req->lun);
		break;
	default:
		break;
	}

	return err;
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
	uint64_t devid;

	nr = scandir(TGT_DEVICE_SYSFSDIR, &namelist, filter, alphasort);
	if (!nr)
		return;

	for (i = 0; i < nr; i++) {

		for (p = namelist[i]->d_name; !isdigit((int) *p); p++)
			;
		if (tid != atoi(p))
			continue;
		p = strchr(p, ':');
		if (!p)
			continue;
		devid = strtoull(++p, NULL, 10);
		kdevice_destroy(tid, devid);
	}

	for (i = 0; i < nr; i++)
		free(namelist[i]);
	free(namelist);
}

static int system_mgmt(struct tgtadm_req *req, char *params, char *rbuf, int *rlen)
{
	int err = -EINVAL, i, nr, fd;
	struct dirent **namelist;
	char path[PATH_MAX], buf[PATH_MAX], *p;

	if (req->op != OP_DELETE)
		return err;

	nr = scandir(TGT_TARGET_SYSFSDIR, &namelist, filter, alphasort);
	if (!nr)
		return -ENOENT;

	for (i = 0; i < nr; i++) {
		snprintf(path, sizeof(path), TGT_TARGET_SYSFSDIR "/%s/typeid",
			 namelist[i]->d_name);

		fd = open(path, O_RDONLY);
		if (fd < 0)
			continue;
		err = read(fd, buf, sizeof(buf));
		close(fd);
		if (err < 0)
			continue;

		if (req->typeid == atoi(buf)) {
			int tid;

			for (p = namelist[i]->d_name; !isdigit((int) *p); p++)
				;
			tid = atoi(p);
			all_devices_destroy(tid);
			ktarget_destroy(tid);
		}
	}

	for (i = 0; i < nr; i++)
		free(namelist[i]);
	free(namelist);

	return 0;
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

	eprintf("%d %d %d %d %d %" PRIx64 " %" PRIx64 " %s\n", nlh->nlmsg_len,
		req->typeid, req->mode, req->op, req->tid, req->sid, req->lun, params);

	switch (req->mode) {
	case MODE_SYSTEM:
		err = system_mgmt(req, params, rbuf, &rlen);
		break;
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
	nlh->nlmsg_len = NLMSG_LENGTH(rlen);
	res = NLMSG_DATA(nlh);
	res->err = err;

	return err;
}
