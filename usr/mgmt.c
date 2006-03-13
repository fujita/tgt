/*
 * SCSI target management functions
 *
 * Copyright (C) 2005 FUJITA Tomonori <tomof@acm.org>
 * Copyright (C) 2005 Mike Christie <michaelc@cs.wisc.edu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <linux/netlink.h>
#include <linux/types.h>
#include <scsi/scsi_tgt_if.h>

#include "tgtd.h"
#include "log.h"
#include "tgtadm.h"

static void device_create_parser(char *args, char **path, char **devtype)
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

static int target_mgmt(struct tgtadm_req *req, char *params,
		       char *rbuf, int *rlen)
{
	int err = -EINVAL;

	switch (req->op) {
	case OP_NEW:
		err = tgt_target_create(req->typeid);
		break;
	case OP_DELETE:
		err = tgt_target_destroy(req->tid);
		break;
	case OP_BIND:
		err = tgt_target_bind(req->tid, req->host_no);
		break;
	default:
		break;
	}

	return err;
}

static int device_mgmt(struct tgtadm_req *req, char *params,
		       char *rbuf, int *rlen)
{
	int err = -EINVAL;
	char *path, *devtype;

	switch (req->op) {
	case OP_NEW:
		path = devtype = NULL;
		device_create_parser(params, &path, &devtype);
		if (!path)
			eprintf("Invalid path\n");
		else
			err = tgt_device_create(req->tid, req->lun, path);
		break;
	case OP_DELETE:
		err = tgt_device_destroy(req->tid, req->lun);
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

	dprintf("%d %d %d %d %d %" PRIx64 " %" PRIx64 " %s %d\n",
		nlh->nlmsg_len,	req->typeid, req->mode, req->op,
		req->tid, req->sid, req->lun, params, getpid());

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

static int ipc_accept(int afd)
{
	struct sockaddr addr;
	socklen_t len;

	len = sizeof(addr);
	return accept(afd, (struct sockaddr *) &addr, &len);
}

static int ipc_perm(int fd)
{
	struct ucred cred;
	socklen_t len;
	int err;

	len = sizeof(cred);
	err = getsockopt(fd, SOL_SOCKET, SO_PEERCRED, (void *) &cred, &len);
	if (err < 0)
		goto out;

	if (cred.uid || cred.gid) {
		err = -EPERM;
		goto out;
	}
out:
	return err;
}

void ipc_event_handle(struct driver_info *dinfo, int accept_fd)
{
	int fd, err;
	char sbuf[4096], rbuf[4096];
	struct nlmsghdr *nlh;
	struct iovec iov;
	struct msghdr msg;
	struct tgtadm_res *res;
	struct tgtadm_req *req;
	int (*fn) (char *, char *);

	fd = ipc_accept(accept_fd);
	if (fd < 0) {
		eprintf("%d\n", fd);
		return;
	}

	err = ipc_perm(fd);
	if (err < 0)
		goto fail;

	memset(sbuf, 0, sizeof(sbuf));
	memset(rbuf, 0, sizeof(rbuf));

	nlh = (struct nlmsghdr *) sbuf;
	iov.iov_base = nlh;
	iov.iov_len = NLMSG_ALIGN(sizeof(struct nlmsghdr));
	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	err = recvmsg(fd, &msg, MSG_PEEK);
	if (err != NLMSG_ALIGN(sizeof(struct nlmsghdr))) {
		err = -EIO;
		goto fail;
	}

	iov.iov_base = nlh;
	iov.iov_len = NLMSG_ALIGN(nlh->nlmsg_len);
	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	err = recvmsg(fd, &msg, MSG_DONTWAIT);
	if (err < 0)
		goto fail;

	req = NLMSG_DATA(nlh);
	dprintf("%d %d %d %d %d\n", req->mode, req->typeid, err, nlh->nlmsg_len, fd);

	fn = dl_fn(dinfo, req->typeid, DL_FN_IPC_MGMT);
	if (fn)
		err = fn((char *) nlh, rbuf);
	else
		err = tgt_mgmt((char *) nlh, rbuf);

send:
	err = write(fd, nlh, nlh->nlmsg_len);
	if (err < 0)
		eprintf("%d\n", err);

	if (fd > 0)
		close(fd);

	return;
fail:
	nlh = (struct nlmsghdr *) rbuf;
	res = NLMSG_DATA(nlh);
	res->err = err;
	nlh->nlmsg_len = NLMSG_LENGTH(0);
	goto send;
}

int ipc_open(void)
{
	int fd, err;
	struct sockaddr_un addr;

	fd = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (fd < 0)
		return fd;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_LOCAL;
	memcpy((char *) &addr.sun_path + 1, TGT_IPC_NAMESPACE,
	       strlen(TGT_IPC_NAMESPACE));

	if ((err = bind(fd, (struct sockaddr *) &addr, sizeof(addr))) < 0)
		return err;

	if ((err = listen(fd, 32)) < 0)
		return err;

	return fd;
}
