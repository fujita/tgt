/*
 * (C) 2005 FUJITA Tomonori <tomof@acm.org>
 * (C) 2005 Mike Christie <michaelc@cs.wisc.edu>
 *
 * Netlink functions are based on open-iscsi code
 * written by Dmitry Yusupov and Alex Aizman.
 *
 * This code is licenced under the GPL.
 */

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <sys/signal.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <dlfcn.h>

#include <tgt_if.h>
#include "tgtd.h"

#define	NL_BUFSIZE	8192

static struct sockaddr_nl src_addr, dest_addr;
static char *recvbuf, *sendbuf;

static int __nl_write(int fd, int type, char *data, int len)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *) data;
	struct iovec iov;
	struct msghdr msg;

	memset(nlh, 0, sizeof(*nlh));
	nlh->nlmsg_len = len;
	nlh->nlmsg_type = type;
	nlh->nlmsg_flags = 0;
	nlh->nlmsg_pid = getpid();

	iov.iov_base = data;
	iov.iov_len = len;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name= (void*) &dest_addr;
	msg.msg_namelen = sizeof(dest_addr);
	msg.msg_iov = (void *) &iov;
	msg.msg_iovlen = 1;

	return sendmsg(fd, &msg, 0);
}

static int __nl_read(int fd, void *data, int size, int flags)
{
	int rc;
	struct iovec iov;
	struct msghdr msg;

	iov.iov_base = data;
	iov.iov_len = size;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name= (void*) &src_addr;
	msg.msg_namelen = sizeof(src_addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	rc = recvmsg(fd, &msg, flags);

	return rc;
}

int nl_read(int fd)
{
	struct nlmsghdr *nlh;
	struct tgt_event *ev;
	int err;

peek_again:
	err = __nl_read(fd, recvbuf, NLMSG_SPACE(sizeof(*ev)), MSG_PEEK);
	if (err < 0) {
		eprintf("%d\n", err);
		if (errno == EAGAIN || errno == EINTR)
			goto peek_again;
		return err;
	}

	nlh = (struct nlmsghdr *) recvbuf;
	ev = (struct tgt_event *) NLMSG_DATA(nlh);

	dprintf("nl_event_handle %d %d\n", nlh->nlmsg_type, nlh->nlmsg_len);

read_again:
	err = __nl_read(fd, recvbuf, nlh->nlmsg_len, 0);
	if (err < 0) {
		eprintf("%d\n", err);
		if (errno == EAGAIN || errno == EINTR)
			goto read_again;
		return err;
	}

	return err;
}

static int cmd_queue(int fd, char *reqbuf, char *resbuf)
{
	int result, len = 0;
	struct tgt_event *ev_req = (struct tgt_event *) reqbuf;
	struct tgt_event *ev_res = NLMSG_DATA(resbuf);
	uint64_t cid = ev_req->k.cmd_req.cid;
	uint8_t *scb;

	memset(resbuf, 0, NL_BUFSIZE);
	scb = (uint8_t *) ev_req->data;
	dprintf("%" PRIu64 " %x\n", cid, scb[0]);

	/*
	 * TODO match tid to protocol and route cmd to correct userspace
	 * protocol module
	 */
	result = scsi_cmd_process(ev_req->k.cmd_req.tid,
				   ev_req->k.cmd_req.dev_id, scb,
				   (uint8_t *) ev_res->data, &len);

	memset(ev_res, 0, sizeof(*ev_res));
	ev_res->u.cmd_res.cid = cid;
	ev_res->u.cmd_res.len = len;
	ev_res->u.cmd_res.result = result;


	log_error("scsi_cmd_process res %d len %d\n", result, len);

	return __nl_write(fd, TGT_UEVENT_CMD_RES, resbuf,
			  NLMSG_SPACE(sizeof(*ev_res) + len));
}

void nl_event_handle(int fd)
{
	struct nlmsghdr *nlh;
	struct tgt_event *ev;
	int err;
	void (*fn) (char *);

	err = nl_read(fd);
	if (err < 0)
		return;

	nlh = (struct nlmsghdr *) recvbuf;
	ev = (struct tgt_event *) NLMSG_DATA(nlh);

	switch (nlh->nlmsg_type) {
	case TGT_KEVENT_CMD_REQ:
		cmd_queue(fd, NLMSG_DATA(recvbuf), sendbuf);
		break;
	case TGT_KEVENT_TARGET_PASSTHRU:
		fn = dlsym(dl_handles[0], "async_event");
		if (fn)
			fn(NLMSG_DATA(recvbuf));
		break;
	default:
		/* kernel module bug */
		eprintf("unknown event %u\n", nlh->nlmsg_type);
		exit(-1);
		break;
	}
}

int nl_cmd_call(int fd, int type, char *data, int size, char *rbuf)
{
	int err;
	struct nlmsghdr *nlh;

	err = __nl_write(fd, type, data, size);
	if (err < 0)
		return err;

	err = nl_read(fd);

	if (rbuf) {
		nlh = (struct nlmsghdr *) recvbuf;
		memcpy(rbuf, nlh, nlh->nlmsg_len);
	}

	return err;
}

static void nl_start(int fd)
{
	int err;
	struct tgt_event *ev;
	struct nlmsghdr *nlh;
	char rbuf[8192];
	char nlmsg[NLMSG_SPACE(sizeof(struct tgt_event))];

	err = nl_cmd_call(fd, TGT_UEVENT_START, nlmsg,
			  NLMSG_SPACE(sizeof(struct tgt_event)), rbuf);

	nlh = (struct nlmsghdr *) rbuf;
	ev = (struct tgt_event *) NLMSG_DATA(nlh);

	if (err < 0 || ev->k.event_res.err < 0) {
		eprintf("%d %d\n", err, ev->k.event_res.err);
		exit(-1);
	}
}

int nl_open(void)
{
	int fd, err;

	sendbuf = malloc(NL_BUFSIZE * 2);
	if (!sendbuf)
		return -ENOMEM;
	recvbuf = sendbuf + NL_BUFSIZE;

	fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_TGT);
	if (fd < 0) {
		eprintf("%d\n", fd);
		return fd;
	}

	memset(&src_addr, 0, sizeof(src_addr));
	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_pid = getpid();
	src_addr.nl_groups = 0; /* not in mcast groups */

	err = bind(fd, (struct sockaddr *)&src_addr, sizeof(src_addr));
	if (err < 0) {
		eprintf("%d\n", fd);
		goto out;
	}

	memset(&dest_addr, 0, sizeof(dest_addr));
	dest_addr.nl_family = AF_NETLINK;
	dest_addr.nl_pid = 0; /* kernel */
	dest_addr.nl_groups = 0; /* unicast */

	nl_start(fd);

	return fd;

out:
	close(fd);
	return err;
}
