/*
 * Unix domain socket for ipc
 *
 * (C) 2005 FUJITA Tomonori <tomof@acm.org>
 * (C) 2005 Mike Christie <michaelc@cs.wisc.edu>
 * This code is licenced under the GPL.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <inttypes.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <asm/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>

#include "tgtd.h"
#include "tgtadm.h"
#include "dl.h"

struct tgt_task {
	int fd;
};

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

void pipe_event_handle(int fd)
{
	struct nlmsghdr *nlh;
	struct iovec iov;
	struct msghdr msg;
	char buf[1024];
	struct tgtadm_res *res;
	struct tgt_task *task;
	int err;

	nlh = (struct nlmsghdr *) buf;
	iov.iov_base = nlh;
	iov.iov_len = NLMSG_ALIGN(sizeof(struct nlmsghdr));
	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	err = recvmsg(fd, &msg, MSG_PEEK);
	if (err != NLMSG_ALIGN(sizeof(struct nlmsghdr)))
		return;

	iov.iov_base = nlh;
	iov.iov_len = NLMSG_ALIGN(nlh->nlmsg_len);
	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	err = recvmsg(fd, &msg, MSG_DONTWAIT);
	if (err < 0)
		return;

	res = NLMSG_DATA(nlh);
	dprintf("%d %d %lx\n", err, nlh->nlmsg_len, res->addr);

	task = (struct tgt_task *) res->addr;
	if (!task)
		return;

	dprintf("%d\n", task->fd);

	err = write(task->fd, nlh, nlh->nlmsg_len);
	close(task->fd);
	free(task);
}

void ipc_event_handle(struct driver_info *dinfo, int accept_fd)
{
	int fd, err, done = 0;
	char sbuf[4096], rbuf[4096];
	struct nlmsghdr *nlh;
	struct iovec iov;
	struct msghdr msg;
	struct tgtadm_res *res;
	struct tgtadm_req *req;
	struct tgt_task *task;
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

	task = calloc(1, sizeof(*task));
	if (!task) {
		err = -ENOMEM;
		goto fail;
	}
	task->fd = fd;

	req = NLMSG_DATA(nlh);
	dprintf("%d %d %d %d %d\n", req->mode, req->typeid, err, nlh->nlmsg_len, fd);

	switch (req->mode) {
	case MODE_DEVICE:
		dprintf("%d %d %d %lx\n",
			req->tid, err, nlh->nlmsg_len, (unsigned long) task);
		req->addr = (unsigned long) task;
		write(poll_array[POLLS_PER_DRV + req->tid].fd,
		      sbuf, NLMSG_ALIGN(nlh->nlmsg_len));
		break;
	default:
		fn = dl_ipc_fn(dinfo, req->typeid);
		if (fn)
			err = fn((char *) nlh, rbuf);
		else
			err = tgt_mgmt((char *) nlh, rbuf);
		done = 1;
	}

	if (!done)
		return;

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
