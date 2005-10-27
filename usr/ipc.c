/*
 * Unix domain socket for ipc
 *
 * (C) 2005 FUJITA Tomonori <tomof@acm.org>
 * (C) 2005 Mike Christie <michaelc@cs.wisc.edu>
 * This code is licenced under the GPL.
 */

#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <asm/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>

#include "tgtd.h"
#include "tgtadm.h"
#include "dl.h"

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

void ipc_event_handle(int accept_fd)
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

	dprintf("%s %d %d\n", req->driver, err, nlh->nlmsg_len);

	fn = dl_ipc_fn(req->driver);
	if (!fn) {
		eprintf("Cannot handle event %s\n", req->driver);
		err = -EINVAL;
		goto fail;
	}
	err = fn((char *) nlh, rbuf);

send:
	err = write(fd, nlh, nlh->nlmsg_len);

	if (fd > 0)
		close(fd);

	if (err < 0)
		eprintf("%d\n", err);

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
