/*
 * (C) 2005 FUJITA Tomonori <tomof@acm.org>
 *
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

#include <stgt_if.h>

extern int nl_fd;
extern int request_execute(int fd, int type, struct iovec *iovp, int count, int *res);

#define STGT_IPC_NAMESPACE "STGT_IPC_ABSTRACT_NAMESPACE"

int ipc_listen(void)
{
	int fd, err;
	struct sockaddr_un addr;

	fd = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (fd < 0)
		return fd;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_LOCAL;
	memcpy((char *) &addr.sun_path + 1, STGT_IPC_NAMESPACE,
	       strlen(STGT_IPC_NAMESPACE));

	if ((err = bind(fd, (struct sockaddr *) &addr, sizeof(addr))) < 0)
		return err;

	if ((err = listen(fd, 32)) < 0)
		return err;

	return fd;
}

static int ipc_exec(struct nlmsghdr *nlh, char *data, int len, int *res)
{
	int err;
	struct iovec iov;

	iov.iov_base = data;
	iov.iov_len = len;

	err = request_execute(nl_fd, nlh->nlmsg_type, &iov, 1, res);

	return err;
}

int ipc_recv(int accept_fd)
{
	struct sockaddr addr;
	struct ucred cred;
	int fd, err, res;
	socklen_t len;
	struct stgt_event *ev;
	char nlm_ev[8192], *data;
	struct nlmsghdr *nlh = (struct nlmsghdr *) nlm_ev;
	struct iovec iov;
	struct msghdr msg;

	printf("%s %d\n", __FUNCTION__, __LINE__);

	len = sizeof(addr);
	if ((fd = accept(accept_fd, (struct sockaddr *) &addr, &len)) < 0) {
		if (errno == EINTR)
			err = -EINTR;
		else
			err = -EIO;

		goto out;
	}

	len = sizeof(cred);
	err = getsockopt(fd, SOL_SOCKET, SO_PEERCRED, (void *) &cred, &len);
	if (err < 0)
		goto send;

	if (cred.uid || cred.gid) {
		err = -EPERM;
		goto send;
	}

	iov.iov_base = nlh;
	iov.iov_len = NLMSG_ALIGN(sizeof(struct nlmsghdr));
	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	err = recvmsg(fd, &msg, MSG_PEEK);
	if (err != NLMSG_ALIGN(sizeof(struct nlmsghdr))) {
		err = -EIO;
		goto out;
	}

	iov.iov_base = nlh;
	iov.iov_len = NLMSG_ALIGN(nlh->nlmsg_len);
	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	err = recvmsg(fd, &msg, MSG_DONTWAIT);
	if (err < 0)
		goto out;
	data = NLMSG_DATA(nlh);

	err = ipc_exec(nlh, data,
		       nlh->nlmsg_len - NLMSG_ALIGN(sizeof(struct nlmsghdr)), &res);

	printf("%s %d %d %d\n", __FUNCTION__, __LINE__, err, res);

send:
	nlh->nlmsg_len = NLMSG_SPACE(sizeof(*ev));
	nlh->nlmsg_type = STGT_KEVENT_RESPONSE;
	nlh->nlmsg_flags = 0;
	nlh->nlmsg_pid = 0;
	ev = NLMSG_DATA(nlh);
	ev->k.event_res.err = res;

	err = write(fd, nlh, NLMSG_SPACE(sizeof(*ev)));

out:
	if (fd > 0)
		close(fd);
	return err;
}
