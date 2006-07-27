/*
 * SCSI target daemon management interface
 *
 * Copyright (C) 2005 FUJITA Tomonori <tomof@acm.org>
 * Copyright (C) 2005 Mike Christie <michaelc@cs.wisc.edu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */
#include <ctype.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>

#include "tgtd.h"
#include "tgtadm.h"
#include "driver.h"

#undef eprintf
#define eprintf(fmt, args...)						\
do {									\
	fprintf(stderr, "%s(%d) " fmt, __FUNCTION__, __LINE__, ##args);	\
} while (0)

#undef dprintf
#define dprintf eprintf

#define BUFSIZE 4096

static char program_name[] = "tgtadm";

static struct option const long_options[] =
{
	{"driver", required_argument, NULL, 'n'},
	{"op", required_argument, NULL, 'o'},
	{"tid", required_argument, NULL, 't'},
	{"sid", required_argument, NULL, 's'},
	{"cid", required_argument, NULL, 'c'},
	{"lun", required_argument, NULL, 'l'},
	{"params", required_argument, NULL, 'p'},
	{"user", no_argument, NULL, 'u'},
	{"hostno", required_argument, NULL, 'i'},
	{"version", no_argument, NULL, 'v'},
	{"help", no_argument, NULL, 'h'},
	{NULL, 0, NULL, 0},
};

static void usage(int status)
{
	if (status != 0)
		fprintf(stderr, "Try `%s --help' for more information.\n", program_name);
	else {
		printf("Usage: %s [OPTION]\n", program_name);
		printf("\
Linux Target Framework Administration Utility.\n\
\n\
  --op new --tid=[id] --params [name]\n\
                        add a new target with [id]. [id] must not be zero.\n\
  --op delete --tid=[id]\n\
                        delete specific target with [id]. The target must\n\
                        have no active sessions.\n\
  --op new --tid=[id] --lun=[lun] --params Path=[path]\n\
                        add a new logical unit with [lun] to specific\n\
                        target with [id]. The logical unit is offered\n\
                        to the initiators. [path] must be block device files\n\
                        (including LVM and RAID devices) or regular files.\n\
  --op delete --tid=[id] --lun=[lun]\n\
                        delete specific logical unit with [lun] that\n\
                        the target with [id] has.\n\
  --op delete --tid=[id] --sid=[sid] --cid=[cid]\n\
                        delete specific connection with [cid] in a session\n\
                        with [sid] that the target with [id] has.\n\
                        If the session has no connections after\n\
                        the operation, the session will be deleted\n\
                        automatically.\n\
  --op delete           stop all activity.\n\
  --op update --tid=[id] --params=key1=value1,key2=value2,...\n\
                        change the target parameters of specific\n\
                        target with [id].\n\
  --op new --tid=[id] --user --params=[user]=[name],Password=[pass]\n\
                        add a new account with [pass] for specific target.\n\
                        [user] could be [IncomingUser] or [OutgoingUser].\n\
                        If you don't specify a target (omit --tid option),\n\
                        you add a new account for discovery sessions.\n\
  --op delete --tid=[id] --user --params=[user]=[name]\n\
                        delete specific account having [name] of specific\n\
                        target. [user] could be [IncomingUser] or\n\
                        [OutgoingUser].\n\
                        If you don't specify a target (omit --tid option),\n\
                        you delete the account for discovery sessions.\n\
  --version             display version and exit\n\
  --help                display this help and exit\n\
\n\
Report bugs to <stgt-devel@lists.berlios.de>.\n");
	}
	exit(status == 0 ? 0 : -1);
}

static int ipc_mgmt_connect(int *fd)
{
	int err;
	struct sockaddr_un addr;

	*fd = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (*fd < 0) {
		eprintf("Cannot create a socket %s\n", strerror(errno));
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_LOCAL;
	memcpy((char *) &addr.sun_path + 1, TGT_IPC_NAMESPACE, strlen(TGT_IPC_NAMESPACE));

	err = connect(*fd, (struct sockaddr *) &addr, sizeof(addr));
	if (err < 0) {
		eprintf("Cannot connect to tgtd %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

static int ipc_mgmt_res(int fd)
{
	struct tgtadm_res *res;
	char buf[BUFSIZE];
	int err, len = (void *) res->data - (void *) res;

	err = read(fd, buf, len);
	if (err < 0) {
		eprintf("Cannot read from tgtd %s\n", strerror(errno));
		return -1;
	}

	res = (struct tgtadm_res *) buf;
	if (res->err) {
		eprintf("Error %d\n", res->err);
		return -1;
	}

	dprintf("got the response %d %d\n", res->err, res->len);

	len = res->len - len;
	if (!len)
		return 0;

	while (len) {
		int t;
		memset(buf, 0, sizeof(buf));
		t = min_t(int, sizeof(buf), len);
		err = read(fd, buf, t);
		if (err < 0) {
			eprintf("Cannot read from tgtd %s\n", strerror(errno));
			return -1;
		}
		printf("%s", buf);
		len -= t;
	}

	return 0;
}

static int ipc_mgmt_req(struct tgtadm_req *req)
{
	int err, fd = 0;

	err = ipc_mgmt_connect(&fd);
	if (err < 0)
		goto out;

	err = write(fd, (char *) req, req->len);
	if (err < 0) {
		eprintf("Cannot send to tgtd %s\n", strerror(errno));
		goto out;
	}

	dprintf("sent to tgtd %d\n", err);

	err = ipc_mgmt_res(fd);
out:
	if (fd > 0)
		close(fd);
	return err;
}

static int set_to_mode(uint32_t set)
{
	int mode = MODE_SYSTEM;

	if (set & (1 << MODE_USER))
		mode = MODE_USER;
	else if (set & (1 << MODE_DEVICE))
		mode = MODE_DEVICE;
	else if (set & (1 << MODE_CONNECTION))
		mode = MODE_CONNECTION;
	else if (set & (1 << MODE_SESSION))
		mode = MODE_SESSION;
	else if (set & (1 << MODE_TARGET))
		mode = MODE_TARGET;

	return mode;
}

static int str_to_op(char *str)
{
	int op;

	if (!strcmp("new", str))
		op = OP_NEW;
	else if (!strcmp("delete", str))
		op = OP_DELETE;
	else if (!strcmp("bind", str))
		op = OP_BIND;
	else if (!strcmp("show", str))
		op = OP_SHOW;
	else
		op = -1;

	return op;
}

int main(int argc, char **argv)
{
	int ch, longindex;
	int err = -EINVAL, op = -1, len = 0;
	int tid = -1;
	uint32_t cid = 0, set = 0, hostno = 0;
	uint64_t sid = 0, lun = 0;
	char *params = NULL, *lldname = NULL;
	struct tgtadm_req *req;
	char buf[BUFSIZE];

	optind = 1;
	while ((ch = getopt_long(argc, argv, "n:o:t:s:c:l:p:uvh",
				 long_options, &longindex)) >= 0) {
		switch (ch) {
		case 'n':
			lldname = optarg;
			break;
		case 'o':
			op = str_to_op(optarg);
			break;
		case 't':
			tid = strtol(optarg, NULL, 10);
			set |= (1 << MODE_TARGET);
			break;
		case 's':
			sid = strtoull(optarg, NULL, 10);
			set |= (1 << MODE_SESSION);
			break;
		case 'c':
			cid = strtoul(optarg, NULL, 10);
			set |= (1 << MODE_CONNECTION);
			break;
		case 'l':
			lun = strtoull(optarg, NULL, 10);
			set |= (1 << MODE_DEVICE);
			break;
		case 'i':
			hostno = strtol(optarg, NULL, 10);
			break;
		case 'b':
			break;
		case 'p':
			params = optarg;
			break;
		case 'u':
			set |= (1 << MODE_USER);
			break;
		case 'v':
			printf("%s\n", program_name);
			exit(0);
			break;
		case 'h':
			usage(0);
			break;
		default:
			usage(-1);
		}
	}
	if (op < 0) {
		eprintf("You must specify the operation type\n");
		goto out;
	}

	if (optind < argc) {
		fprintf(stderr, "unrecognized: ");
		while (optind < argc)
			fprintf(stderr, "%s", argv[optind++]);
		fprintf(stderr, "\n");
		usage(-1);
	}

	memset(buf, 0, sizeof(buf));

	req = (struct tgtadm_req *) buf;
	strncpy(req->lld, lldname, sizeof(req->lld));
	req->mode = set_to_mode(set);
	req->op = op;
	req->tid = tid;
	req->sid = sid;
	req->lun = lun;
	req->host_no = hostno;

	if (params) {
		len = min(strlen(params), sizeof(buf) - len);
		strncpy((char *) req->data, params, len);
	}
	req->len = ((char *) req->data - (char *) req) + len;

	err = ipc_mgmt_req(req);
out:
	return err;
}
