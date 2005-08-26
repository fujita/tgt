/*
 * Event notification code.
 * (C) 2005 FUJITA Tomonori <tomof@acm.org>
 * This code is licenced under the GPL.
 *
 * Netlink functions are taken from open-iscsi code
 * written by Dmitry Yusupov and Alex Aizman.
 */

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/poll.h>

#include <asm/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>

#include <stgt_if.h>

#define eprintf(fmt, args...)						\
do {									\
	fprintf(stderr, "%s(%d) " fmt, __FUNCTION__, __LINE__, args);	\
} while (0)

extern int disk_execute_cmnd(int tid, uint32_t lun, char *scb, char *data);

static struct sockaddr_nl src_addr, dest_addr;
static void *nlm_recvbuf;
static void *nlm_sendbuf;

static int nl_write(int fd, int type, struct iovec *iovp, int count)
{
	int i, datalen;
	struct iovec iov;
	struct msghdr msg;
	struct nlmsghdr *nlh;

	for (datalen = 0, i = 0; i < count; i++)
		datalen += iovp[i].iov_len;

	nlh = nlm_sendbuf;
	memset(nlh, 0, NLMSG_SPACE(datalen));

	nlh->nlmsg_len = NLMSG_SPACE(datalen);
	nlh->nlmsg_type = type;
	nlh->nlmsg_flags = 0;
	nlh->nlmsg_pid = getpid();

	for (datalen = 0, i = 0; i < count; i++) {
		memcpy(NLMSG_DATA(nlh) + datalen, iovp[i].iov_base,
		       iovp[i].iov_len);
		datalen += iovp[i].iov_len;
	}

	iov.iov_base = (void *) nlh;
	iov.iov_len = nlh->nlmsg_len;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name= (void*) &dest_addr;
	msg.msg_namelen = sizeof(dest_addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	return sendmsg(fd, &msg, 0);
}

static int nl_read(int ctrl_fd, char *data, int size, int flags)
{
	int rc;
	struct iovec iov;
	struct msghdr msg;

	iov.iov_base = data;
	iov.iov_len = size;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name= (void*)&src_addr;
	msg.msg_namelen = sizeof(src_addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	rc = recvmsg(ctrl_fd, &msg, flags);

	return rc;
}

static int nl_open(void)
{
	int nl_fd, res;
	struct stgt_event ev;
	struct iovec iov;

	if (!(nl_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_STGT)))
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

	iov.iov_base = &ev;
	iov.iov_len = sizeof(ev);

	if ((res = nl_write(nl_fd, STGT_UEVENT_START, &iov, 1)) < 0) {
		return res;
	}

	return nl_fd;
}

static int
nlpayload_read(int ctrl_fd, char *data, int count, int flags)
{
	int rc;
	struct iovec iov;
	struct msghdr msg;

	iov.iov_base = nlm_recvbuf;
	iov.iov_len = NLMSG_SPACE(count);
	memset(iov.iov_base, 0, iov.iov_len);

	memset(&msg, 0, sizeof(msg));
	msg.msg_name= (void*)&src_addr;
	msg.msg_namelen = sizeof(src_addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	rc = recvmsg(ctrl_fd, &msg, flags);

	memcpy(data, NLMSG_DATA(iov.iov_base), count);

	return rc;
}

static int execute_cmnd(int fd, char *recvbuf, char *sendbuf)
{
	int err;
	struct iovec iov[2];
	struct stgt_event uev, *ev = (struct stgt_event *) recvbuf;
	uint8_t *scb;

	scb = recvbuf + sizeof(*ev);
	eprintf("%" PRIu64 " %x\n", ev->u.msg_scsi_cmnd.cid, scb[0]);

	err = disk_execute_cmnd(ev->u.msg_scsi_cmnd.tid,
				ev->u.msg_scsi_cmnd.lun,
				scb, sendbuf);
	if (err < 0)
		return err;

	uev.u.msg_scsi_cmnd.size = err;
	uev.u.msg_scsi_cmnd.cid = ev->u.msg_scsi_cmnd.cid;

	iov[0].iov_base = (void *) &uev;
	iov[0].iov_len = sizeof(uev);
	iov[1].iov_base = sendbuf;
	iov[1].iov_len = err;

	err = nl_write(fd, STGT_UEVENT_SCSI_CMND_RES, iov, err ? 2 : 1);

	return 0;
}

static void handle_events(int fd)
{
	struct nlmsghdr *nlh;
	struct stgt_event *ev;
	char nlm_ev[NLMSG_SPACE(sizeof(*ev))];
	int err, ev_size;
	char recvbuf[4096], sendbuf[4096];

retry:
	if ((err = nl_read(fd, nlm_ev, NLMSG_SPACE(sizeof(*ev)), MSG_PEEK)) < 0) {
		if (errno == EAGAIN)
			return;
		if (errno == EINTR)
			goto retry;
		exit(1);
	}

	nlh = (struct nlmsghdr *) nlm_ev;
	ev = (struct stgt_event *) NLMSG_DATA(nlm_ev);

	ev_size = nlh->nlmsg_len - NLMSG_ALIGN(sizeof(struct nlmsghdr));

	eprintf("%d %d\n", nlh->nlmsg_type, ev_size);

	if ((err = nlpayload_read(fd, recvbuf, ev_size, 0)) < 0) {
		eprintf("%d\n", err);
		exit(err);
	}

	switch (nlh->nlmsg_type) {
	case STGT_KEVENT_SCSI_CMND_REQ:
		memset(sendbuf, 0, sizeof(sendbuf));
		execute_cmnd(fd, recvbuf, sendbuf);
		break;
	default:
		exit(-1);
		break;
	}
}

#define POLL_CTRL 0

int main(int argc, char **argv)
{
	static struct pollfd poll_array[POLL_CTRL + 1];
	int fd, err;

	nlm_sendbuf = malloc(8192);
	nlm_recvbuf = malloc(8192);

	memset(poll_array, 0, sizeof(poll_array));

	if ((fd = nl_open()) < 0)
		exit(fd);

	poll_array[POLL_CTRL].fd = fd;
	poll_array[POLL_CTRL].events = POLLIN;

	while (1) {
		if ((err = poll(poll_array, 1, -1)) < 0) {
			if (errno != EINTR) {
				eprintf("%d %d\n", err, errno);
				exit(1);
			}
			continue;
		}

		if (poll_array[POLL_CTRL].revents)
			handle_events(fd);
	}

	return 0;
}
