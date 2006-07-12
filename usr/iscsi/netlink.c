/*
 * iSCSI Netlink/Linux Interface
 *
 * Copyright (C) 2004 Dmitry Yusupov, Alex Aizman
 * maintained by open-iscsi@googlegroups.com
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * See the file COPYING included with this distribution for more details.
 */

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <linux/types.h>
#include <linux/netlink.h>

#include "iscsid.h"
#include "tgtadm.h"

#define NL_BUFSIZE 4096

static struct sockaddr_nl saddr, daddr;

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

static int nl_read(char *buf)
{
	struct nlmsghdr *nlh;
	int err;

peek_again:
	err = __nl_read(nl_fd, buf, NLMSG_LENGTH(0), MSG_PEEK);
	if (err < 0) {
		eprintf("%d\n", err);
		if (errno == EAGAIN || errno == EINTR)
			goto peek_again;
		return err;
	}

	nlh = (struct nlmsghdr *) buf;

/* 	dprintf("%d %d %d\n", nlh->nlmsg_type, nlh->nlmsg_len, getpid()); */
read_again:
	err = __nl_read(nl_fd, buf, nlh->nlmsg_len, 0);
	if (err < 0) {
		eprintf("%d\n", err);
		if (errno == EAGAIN || errno == EINTR)
			goto read_again;
		return err;
	}

	return err;
}

static int __kipc_call(struct iscsi_uevent *ev, int len)
{
	struct nlmsghdr *nlh;
	char sbuf[NL_BUFSIZE];
	int err;

	nlh = (struct nlmsghdr *) sbuf;
	memset(sbuf, 0, NL_BUFSIZE);
	memcpy(NLMSG_DATA(nlh), ev, len);

	len = NLMSG_SPACE(len);
	nlh->nlmsg_pid = getpid();
	nlh->nlmsg_len = len;
	nlh->nlmsg_type = ev->type;

	err = sendto(nl_fd, nlh, len, 0, (struct sockaddr *) &daddr, sizeof(daddr));
	if (err < 0) {
		eprintf("%d\n", err);
		return err;
	}

	memset(sbuf, 0, NL_BUFSIZE);
	err = nl_read(sbuf);
	if (err < 0) {
		eprintf("%d\n", err);
		return err;
	}

	memcpy(ev, NLMSG_DATA(sbuf), sizeof(*ev));

	return err;
}

static int kcreate_session(uint64_t transport_handle, uint32_t initial_cmdsn,
		uint32_t *out_sid, uint32_t *out_hostno)
{
	int rc;
	struct iscsi_uevent ev;

	dprintf("%"PRIx64 " %u %u %u\n",
		transport_handle, initial_cmdsn, *out_sid, *out_hostno);

	memset(&ev, 0, sizeof(struct iscsi_uevent));

	ev.type = ISCSI_UEVENT_CREATE_SESSION;
	ev.transport_handle = transport_handle;
	ev.u.c_session.initial_cmdsn = initial_cmdsn;

	if ((rc = __kipc_call(&ev, sizeof(ev))) < 0) {
		return rc;
	}

	*out_hostno = ev.r.c_session_ret.host_no;
	*out_sid = ev.r.c_session_ret.sid;

	return 0;
}

static int kdestroy_session(uint64_t transport_handle, uint32_t sid)
{
	int rc;
	struct iscsi_uevent ev;

	memset(&ev, 0, sizeof(struct iscsi_uevent));

	ev.type = ISCSI_UEVENT_DESTROY_SESSION;
	ev.transport_handle = transport_handle;
	ev.u.d_session.sid = sid;

	if ((rc = __kipc_call(&ev, sizeof(ev))) < 0) {
		return rc;
	}

	return 0;
}

static int kcreate_conn(uint64_t transport_handle, uint32_t sid,
		       uint32_t cid, uint32_t *out_cid)
{
	int rc;
	struct iscsi_uevent ev;

	dprintf("%"PRIx64 " %u %u\n", transport_handle, sid, cid);

	memset(&ev, 0, sizeof(struct iscsi_uevent));

	ev.type = ISCSI_UEVENT_CREATE_CONN;
	ev.transport_handle = transport_handle;
	ev.u.c_conn.cid = cid;
	ev.u.c_conn.sid = sid;

	if ((rc = __kipc_call(&ev, sizeof(ev))) < 0) {
		eprintf("%d\n", rc);
		return rc;
	}

	if ((int)ev.r.c_conn_ret.cid == -1)
		return -EIO;

	*out_cid = ev.r.c_conn_ret.cid;
	return 0;
}

static int kdestroy_conn(uint64_t transport_handle, uint32_t sid, uint32_t cid)
{
	int rc;
	struct iscsi_uevent ev;

	memset(&ev, 0, sizeof(struct iscsi_uevent));

	ev.type = ISCSI_UEVENT_DESTROY_CONN;
	ev.transport_handle = transport_handle;
	ev.u.d_conn.sid = sid;
	ev.u.d_conn.cid = cid;

	if ((rc = __kipc_call(&ev, sizeof(ev))) < 0) {
		eprintf("%d\n", rc);
	}

	return 0;
}

static int
kbind_conn(uint64_t transport_handle, uint32_t sid, uint32_t cid,
	   uint64_t transport_eph, int is_leading, int *retcode)
{
	int rc;
	struct iscsi_uevent ev;

	ev.type = ISCSI_UEVENT_BIND_CONN;
	ev.transport_handle = transport_handle;
	ev.u.b_conn.sid = sid;
	ev.u.b_conn.cid = cid;
	ev.u.b_conn.transport_eph = transport_eph;
	ev.u.b_conn.is_leading = is_leading;

	if ((rc = __kipc_call(&ev, sizeof(ev))) < 0) {
		return rc;
	}

	*retcode = ev.r.retcode;

	return 0;
}

static int
kstop_conn(uint64_t transport_handle, uint32_t sid, uint32_t cid, int flag)
{
	int rc;
	struct iscsi_uevent ev;

	memset(&ev, 0, sizeof(struct iscsi_uevent));

	ev.type = ISCSI_UEVENT_STOP_CONN;
	ev.transport_handle = transport_handle;
	ev.u.stop_conn.sid = sid;
	ev.u.stop_conn.cid = cid;
	ev.u.stop_conn.flag = flag;

	if ((rc = __kipc_call(&ev, sizeof(ev))) < 0) {
		return rc;
	}

	return 0;
}

static int
kstart_conn(uint64_t transport_handle, uint32_t sid, uint32_t cid,
	    int *retcode)
{
	int rc;
	struct iscsi_uevent ev;

	memset(&ev, 0, sizeof(struct iscsi_uevent));

	ev.type = ISCSI_UEVENT_START_CONN;
	ev.transport_handle = transport_handle;
	ev.u.start_conn.sid = sid;
	ev.u.start_conn.cid = cid;

	if ((rc = __kipc_call(&ev, sizeof(ev))) < 0) {
		return rc;
	}

	*retcode = ev.r.retcode;
	return 0;
}

static int
kset_param(uint64_t transport_handle, uint32_t sid, uint32_t cid,
	   enum iscsi_param param, void *value, int len, int *retcode)
{
	struct iscsi_uevent *ev;
	char setparam_buf[NL_BUFSIZE];
	int rc;

	memset(setparam_buf, 0, sizeof(setparam_buf));
	ev = (struct iscsi_uevent *) setparam_buf;
	ev->type = ISCSI_UEVENT_SET_PARAM;
	ev->transport_handle = transport_handle;
	ev->u.set_param.sid = sid;
	ev->u.set_param.cid = cid;
	ev->u.set_param.param = param;
	ev->u.set_param.len = len;
	memcpy(setparam_buf + sizeof(*ev), value, len);

	if ((rc = __kipc_call(ev, sizeof(*ev) + len)) < 0) {
		return rc;
	}

	*retcode = ev->r.retcode;

	return 0;
}

static int transport_handle_init(void)
{
	int fd, err;
	char buf[64];

	fd = open("/sys/class/iscsi_transport/iscsi_tcp_tgt/handle", O_RDONLY);
	if (fd < 0)
		return fd;
	err = read(fd, buf, sizeof(buf));
	if (err < 0)
		goto out;
	thandle = strtoull(buf, NULL, 10);
	dprintf("%" PRIx64 "\n", thandle);
	err = 0;
out:
	close(fd);
	return err;
}

int iscsi_nl_init(void)
{
	int err, rsize = 256 * 1024;

	err = transport_handle_init();
	if (err)
		return err;

	nl_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_ISCSI);
	if (nl_fd < 0) {
		eprintf("Fail to create the netlink socket %d\n", errno);
		return err;
	}
	eprintf("create the netlink socket %d\n", nl_fd);

	err = setsockopt(nl_fd, SOL_SOCKET, SO_RCVBUF, &rsize, sizeof(rsize));
	if (err) {
		eprintf("fail to setsockopt %d\n", errno);
		return err;
	}

	memset(&saddr, 0, sizeof(saddr));
	saddr.nl_family = AF_NETLINK;
	saddr.nl_pid = getpid();
	saddr.nl_groups = 0; /* not in mcast groups */
/* 	err = bind(nl_fd, (struct sockaddr *) &saddr, sizeof(saddr)); */
/* 	if (err) { */
/* 		eprintf("can not bind NETLINK_ISCSI socket %d\n", errno); */
/* 		close(nl_fd); */
/* 		return err; */
/* 	} */

	memset(&daddr, 0, sizeof(daddr));
	daddr.nl_family = AF_NETLINK;
	daddr.nl_pid = 0; /* kernel */
	daddr.nl_groups = 0; /* unicast */
	eprintf("create the netlink socket %d %d\n", nl_fd, err);

	return err;
}

struct iscsi_kernel_interface nl_ki = {
	.create_session		= kcreate_session,
	.destroy_session	= kdestroy_session,
	.create_conn		= kcreate_conn,
	.destroy_conn		= kdestroy_conn,
	.bind_conn		= kbind_conn,
	.set_param              = kset_param,
	.start_conn             = kstart_conn,
	.stop_conn              = kstop_conn,
};

struct iscsi_kernel_interface *ki = &nl_ki;
