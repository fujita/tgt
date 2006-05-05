/*
 * Copyright (C) 2006 FUJITA Tomonori <tomof@acm.org>
 * Copyright (C) 2006 Mike Christie
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

static int ipc_connect(void)
{
	int fd, err;
	struct sockaddr_un addr;

	fd = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (fd < 0)
		return fd;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_LOCAL;
	memcpy((char *) &addr.sun_path + 1, ISTGT_NAMESPACE, strlen(ISTGT_NAMESPACE));

	if ((err = connect(fd, (struct sockaddr *) &addr, sizeof(addr))) < 0)
		fd = err;

	return fd;
}

int ipc_mgmt(char *sbuf, char *rbuf)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *) sbuf;
	struct tgtadm_req *req;
	int err = -EINVAL, fd;
	char *params;

	req = NLMSG_DATA(nlh);
	params = (char *) req + sizeof(*req);

	eprintf("%d %d %d %d %d %" PRIx64 " %" PRIx64 " %s\n", nlh->nlmsg_len,
		req->typeid, req->mode, req->op, req->tid, req->sid, req->lun, params);

	fd = ipc_connect();
	if (fd < 0) {
		eprintf("cannot connect istgtd\n");
		return fd;
	}

	err = write(fd, sbuf, nlh->nlmsg_len);
	if (err < 0) {
		eprintf("cannot connect istgtd\n");
		goto out;
	}

out:
	close(fd);

	return err;
}
