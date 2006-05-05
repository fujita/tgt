/*
 * Copyright (C) 2002-2003 Ardis Technolgies <roman@ardistech.com>
 *
 * Released under the terms of the GNU GPL v2.0.
 */

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <linux/netlink.h>
#include <sys/socket.h>

#include "iscsid.h"
#include "tgtadm.h"

struct qelem targets_list = LIST_HEAD_INIT(targets_list);

void target_list_build(struct connection *conn, char *addr, char *name)
{
	struct target *target;

	list_for_each_entry(target, &targets_list, tlist) {
		if (name && strcmp(target->name, name))
			continue;
/* 		if (cops->initiator_access(target->tid, conn->fd) < 0) */
/* 			continue; */

		text_key_add(conn, "TargetName", target->name);
		text_key_add(conn, "TargetAddress", addr);
	}
}

int target_find_by_name(const char *name, int *tid)
{
	struct target *target;

	list_for_each_entry(target, &targets_list, tlist) {
		if (!strcmp(target->name, name)) {
			*tid = target->tid;
			return 0;
		}
	}

	return -ENOENT;
}

struct target* target_find_by_id(int tid)
{
	struct target *target;

	list_for_each_entry(target, &targets_list, tlist) {
		if (target->tid == tid)
			return target;
	}

	return NULL;
}

static int destroy_target(int tid)
{
	struct target* target;

	if (!(target = target_find_by_id(tid)))
		return -ENOENT;

	if (target->nr_sessions)
		return -EBUSY;

	if (!list_empty(&target->sessions_list)) {
		eprintf("bug still have sessions %d\n", tid);
		exit(-1);
	}

	remque(&target->tlist);

	free(target);

	return 0;
}

static int create_target(int tid, char *name)
{
	struct target *target;

	if (!name)
		return -EINVAL;

	dprintf("%d %s\n", tid, name);

	if (!(target = malloc(sizeof(*target))))
		return -ENOMEM;

	memset(target, 0, sizeof(*target));
	memcpy(target->name, name, sizeof(target->name) - 1);

	INIT_LIST_HEAD(&target->tlist);
	INIT_LIST_HEAD(&target->sessions_list);
	target->tid = tid;
	insque(&target->tlist, &targets_list);

	return 0;
}

static int istgt_target_mgmt(struct tgtadm_req *req, char *params)
{
	int err = -EINVAL, tid = req->tid;

	switch (req->op) {
	case OP_NEW:
		err = create_target(tid, params);
		break;
	case OP_DELETE:
		err = destroy_target(tid);
		break;
	default:
		break;
	}

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

void ipc_event(void)
{
	int fd, err;
	char sbuf[4096], rbuf[4096];
	struct nlmsghdr *nlh;
	struct iovec iov;
	struct msghdr msg;
	struct tgtadm_req *req;

	dprintf("ipc\n");

	fd = ipc_accept(ipc_fd);
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

	if (req->mode == MODE_TARGET)
		err = istgt_target_mgmt(req, (char *) req + sizeof(*req));

fail:
	if (fd > 0)
		close(fd);

	return;
}

/* should be moved somewhere */
int ipc_init(void)
{
	int fd, err;
	struct sockaddr_un addr;

	fd = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (fd < 0)
		return fd;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_LOCAL;
	memcpy((char *) &addr.sun_path + 1, ISTGT_NAMESPACE,
	       strlen(ISTGT_NAMESPACE));

	if ((err = bind(fd, (struct sockaddr *) &addr, sizeof(addr))) < 0)
		return err;

	if ((err = listen(fd, 32)) < 0)
		return err;

	ipc_fd = fd;

	return 0;
}
