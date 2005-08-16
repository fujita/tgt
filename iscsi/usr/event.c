/*
 * Event notification code.
 * (C) 2005 FUJITA Tomonori <tomof@acm.org>
 * This code is licenced under the GPL.
 *
 * Some functions are based on open-iscsi code
 * written by Dmitry Yusupov, Alex Aizman.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <asm/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>

#include "iscsid.h"

static struct sockaddr_nl src_addr, dest_addr;

static int nl_write(int fd, void *data, int len)
{
	struct iovec iov[2];
	struct msghdr msg;
	struct nlmsghdr nlh;

	iov[0].iov_base = &nlh;
	iov[0].iov_len = sizeof(nlh);
	iov[1].iov_base = data;
	iov[1].iov_len = NLMSG_SPACE(len) - sizeof(nlh);

	nlh.nlmsg_len = NLMSG_SPACE(len);
	nlh.nlmsg_pid = getpid();
	nlh.nlmsg_flags = 0;
	nlh.nlmsg_type = 0;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name= (void*)&dest_addr;
	msg.msg_namelen = sizeof(dest_addr);
	msg.msg_iov = iov;
	msg.msg_iovlen = 2;

	return sendmsg(fd, &msg, 0);
}

static int nl_read(int fd, void *data, int len)
{
	struct iovec iov[2];
	struct msghdr msg;
	struct nlmsghdr nlh;

	iov[0].iov_base = &nlh;
	iov[0].iov_len = sizeof(nlh);
	iov[1].iov_base = data;
	iov[1].iov_len = len;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name= (void*)&src_addr;
	msg.msg_namelen = sizeof(src_addr);
	msg.msg_iov = iov;
	msg.msg_iovlen = 2;

	return recvmsg(fd, &msg, MSG_DONTWAIT);
}

void handle_iscsi_events(int fd)
{
	struct session *session;
	struct iet_event event;
	int res;

retry:
	if ((res = nl_read(fd, &event, sizeof(event))) < 0) {
		if (errno == EAGAIN)
			return;
		if (errno == EINTR)
			goto retry;
		log_error("read netlink fd (%d)", errno);
		exit(1);
	}

	log_debug(1, "close conn %u session %#" PRIx64 " target %u, state %u",
		  event.cid, event.sid, event.tid, event.state);

	switch (event.state) {
	case E_CONN_CLOSE:
		if (!(session = session_find_id(event.tid, event.sid))) {
			log_warning("session %#" PRIx64 " not found?", event.sid);
			goto retry;
		}

		if (!--session->conn_cnt)
			session_remove(session);
		break;
	default:
		log_warning("%s(%d) %u\n", __FUNCTION__, __LINE__, event.state);
		exit(-1);
		break;
	}
}

int nl_open(void)
{
	int nl_fd, res;

	if (!(nl_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_IET)))
		return -1;

	memset(&src_addr, 0, sizeof(src_addr));
	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_pid = getpid();
	src_addr.nl_groups = 0; /* not in mcast groups */
	if (bind(nl_fd, (struct sockaddr *)&src_addr, sizeof(src_addr))) {
		return -1;
	}

	memset(&dest_addr, 0, sizeof(dest_addr));
	dest_addr.nl_family = AF_NETLINK;
	dest_addr.nl_pid = 0; /* kernel */
	dest_addr.nl_groups = 0; /* unicast */

	if ((res = nl_write(nl_fd, NULL, 0)) < 0) {
		log_error("%s %d\n", __FUNCTION__, res);
		return res;
	}

	return nl_fd;
}
