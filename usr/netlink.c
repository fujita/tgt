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
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <sys/signal.h>
#include <sys/socket.h>
#include <asm/types.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/netlink.h>

#include <scsi/scsi_tgt_if.h>
#include "tgtd.h"
#include "dl.h"

#define	NL_BUFSIZE	1024

int __nl_write(int fd, int type, char *data, int len)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *) data;
	struct sockaddr_nl daddr;

	memset(nlh, 0, sizeof(*nlh));
	nlh->nlmsg_len = len;
	nlh->nlmsg_type = type;
	nlh->nlmsg_flags = 0;
	nlh->nlmsg_pid = getpid();

	memset(&daddr, 0, sizeof(daddr));
	daddr.nl_family = AF_NETLINK;
	daddr.nl_pid = 0;
	daddr.nl_groups = 0;

	return sendto(fd, data, len, 0, (struct sockaddr *) &daddr,
		      sizeof(daddr));
}

static int __nl_read(int fd, void *data, int size, int flags)
{
	struct sockaddr_nl saddr;
	socklen_t slen = sizeof(saddr);

	memset(&saddr, 0, sizeof(saddr));
	saddr.nl_family = AF_NETLINK;
	saddr.nl_pid = getpid();
	saddr.nl_groups = 0; /* not in mcast groups */

	return recvfrom(fd, data, size, flags, (struct sockaddr *) &saddr, &slen);
}

static int nl_read(int fd, char *buf)
{
	struct nlmsghdr *nlh;
	struct tgt_event *ev;
	int err;

peek_again:
	err = __nl_read(fd, buf, NLMSG_SPACE(sizeof(*ev)), MSG_PEEK);
	if (err < 0) {
		eprintf("%d\n", err);
		if (errno == EAGAIN || errno == EINTR)
			goto peek_again;
		return err;
	}

	nlh = (struct nlmsghdr *) buf;
	ev = (struct tgt_event *) NLMSG_DATA(nlh);

	dprintf("%d %d %d\n", nlh->nlmsg_type, nlh->nlmsg_len, getpid());

read_again:
	err = __nl_read(fd, buf, nlh->nlmsg_len, 0);
	if (err < 0) {
		eprintf("%d\n", err);
		if (errno == EAGAIN || errno == EINTR)
			goto read_again;
		return err;
	}

	return err;
}

int nl_cmd_call(int fd, int type, char *sbuf, int slen, char *rbuf, int rlen)
{
	int err;
	struct nlmsghdr *nlh;
	char buf[NL_BUFSIZE];

	err = __nl_write(fd, type, sbuf, slen);
	if (err < 0)
		return err;

	err = nl_read(fd, buf);

	if (rbuf) {
		nlh = (struct nlmsghdr *) buf;
		if (rlen < nlh->nlmsg_len)
			eprintf("Too small rbuf %d %d\n", rlen, nlh->nlmsg_len);
		else
			rlen = nlh->nlmsg_len;

		memcpy(rbuf, nlh, rlen);
	}

	return err;
}

static int ringbuf_init(int pk_fd, struct ringbuf_info *ri)
{
	struct tpacket_req req;
	int err;
	socklen_t len = sizeof(req);
	unsigned int size = RINGBUF_SIZE;
	void *addr;

	req.tp_frame_size = TPACKET_ALIGN(TPACKET_HDRLEN +
					  sizeof(struct tgt_event) +
					  sizeof(struct tgt_cmd));
	req.tp_block_size = size;
	req.tp_frame_nr = req.tp_block_size / req.tp_frame_size;
	req.tp_block_nr = 1;

	err = setsockopt(pk_fd, SOL_PACKET, PACKET_RX_RING, &req, len);
	dprintf("%d %u %u\n", errno, req.tp_frame_size, req.tp_frame_nr);
	if (err < 0)
		return err;

	addr = mmap(0, size, PROT_READ|PROT_WRITE, MAP_SHARED, pk_fd, 0);

	ri->frame_size = req.tp_frame_size;
	ri->frame_nr = req.tp_frame_nr;
	ri->addr = addr;
	ri->idx = 0;

	dprintf("%p\n",addr);

	if (addr == MAP_FAILED) {
		eprintf("fail to mmap %d\n", errno);
		return -EINVAL;
	} else
		return 0;
}

static int tgtd_bind(int nl_fd, int pk_fd)
{
	int err;
	struct tgt_event *ev;
	char sbuf[NL_BUFSIZE], rbuf[NL_BUFSIZE];

	ev = (struct tgt_event *) NLMSG_DATA(sbuf);
	ev->u.tgtd_bind.pk_fd = pk_fd;
	err = nl_cmd_call(nl_fd, TGT_UEVENT_TGTD_BIND, sbuf,
			  NLMSG_SPACE(sizeof(struct tgt_event)),
			  rbuf, NL_BUFSIZE);

	ev = (struct tgt_event *) NLMSG_DATA(rbuf);
	if (err < 0 || ev->k.event_res.err < 0) {
		eprintf("%d %d\n", err, ev->k.event_res.err);
		return -EINVAL;
	}

	return 0;
}

int nl_init(int *nfd, int *pfd, struct ringbuf_info *ri)
{
	int err, nl_fd, pk_fd;

	nl_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_TGT);
	if (nl_fd < 0) {
		eprintf("Fail to create the netlink socket %d\n", errno);
		exit(1);
	}

	pk_fd = socket(PF_PACKET, SOCK_RAW, 0);
	if (pk_fd < 0) {
		eprintf("Fail to create the packet socket %d\n", errno);
		exit(1);
	}

	err = ringbuf_init(pk_fd, ri);
	if (err)
		exit(1);

	err = tgtd_bind(nl_fd, pk_fd);
	if (err)
		exit(1);

	*nfd = nl_fd;
	*pfd = pk_fd;
	return 0;
}
