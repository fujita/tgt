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
#include <scsi/scsi_tgt_if.h>

#include "tgtd.h"
#include "log.h"
#include "tgtadm.h"
#include "driver.h"

#define BUFSIZE 4096

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

static int target_mgmt(int lld_no, struct tgtadm_req *req, char *params,
		       struct tgtadm_res *res, int *rlen)
{
	int err = -EINVAL;

	switch (req->op) {
	case OP_NEW:
		err = tgt_target_create(req->tid);
		if (!err && tgt_drivers[lld_no]->target_create)
			tgt_drivers[lld_no]->target_create(req->tid, params);
		break;
	case OP_DELETE:
		err = tgt_target_destroy(req->tid);
		if (!err && tgt_drivers[lld_no]->target_destroy)
			tgt_drivers[lld_no]->target_destroy(req->tid);
		break;
	case OP_BIND:
		err = tgt_target_bind(req->tid, req->host_no, lld_no);
		break;
	default:
		break;
	}

	res->err = err;
	res->len = (char *) res->data - (char *) res;

	return err;
}

static int device_mgmt(int lld_no, struct tgtadm_req *req, char *params,
		       struct tgtadm_res *res, int *rlen)
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

	res->err = err;
	res->len = (char *) res->data - (char *) res;

	return err;
}

int tgt_mgmt(int lld_no, struct tgtadm_req *req, struct tgtadm_res *res,
	     int len)
{
	int err = -EINVAL;
	char *params = (char *) req->data;

	dprintf("%d %d %d %d %d %" PRIx64 " %" PRIx64 " %s %d\n",
		req->len, lld_no, req->mode, req->op,
		req->tid, req->sid, req->lun, params, getpid());

	switch (req->mode) {
	case MODE_TARGET:
		err = target_mgmt(lld_no, req, params, res, &len);
		break;
	case MODE_DEVICE:
		err = device_mgmt(lld_no, req, params, res, &len);
		break;
	default:
		break;
	}

	return err;
}

static int ipc_accept(int accept_fd)
{
	struct sockaddr addr;
	socklen_t len;
	int fd;

	len = sizeof(addr);
	fd = accept(accept_fd, (struct sockaddr *) &addr, &len);
	if (fd < 0)
		eprintf("can't accept a new connection %s\n", strerror(errno));
	return fd;
}

static int ipc_perm(int fd)
{
	struct ucred cred;
	socklen_t len;
	int err;

	len = sizeof(cred);
	err = getsockopt(fd, SOL_SOCKET, SO_PEERCRED, (void *) &cred, &len);
	if (err) {
		eprintf("can't get sockopt %s\n", strerror(errno));
		return -1;
	}

	if (cred.uid || cred.gid)
		return -EPERM;

	return 0;
}

static void ipc_send_res(int fd, struct tgtadm_res *res)
{
	struct iovec iov;
	struct msghdr msg;
	int err;

	iov.iov_base = res;
	iov.iov_len = res->len;
	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	err = sendmsg(fd, &msg, MSG_DONTWAIT);
	if (err != res->len)
		eprintf("can't write %s\n", strerror(errno));
}

void ipc_event_handle(int accept_fd)
{
	int fd, err;
	char sbuf[BUFSIZE], rbuf[BUFSIZE];
	struct iovec iov;
	struct msghdr msg;
	struct tgtadm_req *req;
	struct tgtadm_res *res;
	int lld_no, len;

	req = (struct tgtadm_req *) sbuf;
	memset(sbuf, 0, sizeof(sbuf));

	fd = ipc_accept(accept_fd);
	if (fd < 0)
		return;

	err = ipc_perm(fd);
	if (err < 0)
		goto out;

	len = (char *) req->data - (char *) req;
	iov.iov_base = req;
	iov.iov_len = len;
	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	err = recvmsg(fd, &msg, MSG_PEEK | MSG_DONTWAIT);
	if (err != len) {
		eprintf("can't read %s\n", strerror(errno));
		goto out;
	}

	if (req->len > sizeof(sbuf) - len) {
		eprintf("too long data %d\n", req->len);
		goto out;
	}

	iov.iov_base = req;
	iov.iov_len = req->len;
	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	err = recvmsg(fd, &msg, MSG_DONTWAIT);
	if (err != req->len) {
		eprintf("can't read %s\n", strerror(errno));
		err = -EIO;
		goto out;
	}

	dprintf("%d %s %d %d %d\n", req->mode, req->lld, err, req->len, fd);
	res = (struct tgtadm_res *) rbuf;
	memset(rbuf, 0, sizeof(rbuf));

	lld_no = get_driver_index(req->lld);
	if (lld_no < 0) {
		eprintf("can't find the driver\n");
		res->err = ENOENT;
		res->len = (char *) res->data - (char *) res;
		goto send;
	}

	err = tgt_mgmt(lld_no, req, res, sizeof(rbuf));
	if (err)
		eprintf("%d %d %d %d\n", req->mode, lld_no, err, res->len);

send:
	ipc_send_res(fd, res);
out:
	if (fd > 0)
		close(fd);

	return;
}

int ipc_open(int *ipc_fd)
{
	int fd, err;
	struct sockaddr_un addr;

	fd = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (fd < 0) {
		eprintf("can't open a socket %s\n", strerror(errno));
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_LOCAL;
	memcpy((char *) &addr.sun_path + 1, TGT_IPC_NAMESPACE,
	       strlen(TGT_IPC_NAMESPACE));

	err = bind(fd, (struct sockaddr *) &addr, sizeof(addr));
	if (err) {
		eprintf("can't bind a socket %s\n", strerror(errno));
		goto out;
	}

	err = listen(fd, 32);
	if (err < 0) {
		eprintf("can't listen a socket %s\n", strerror(errno));
		goto out;
	}

	*ipc_fd = fd;
	return 0;
out:
	close(fd);
	return -1;
}
