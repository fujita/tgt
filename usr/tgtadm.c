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

#include "util.h"
#include "list.h"
#include "tgtd.h"
#include "tgtadm.h"
#include "driver.h"

#undef eprintf
#define eprintf(fmt, args...)						\
do {									\
	fprintf(stderr, "%s(%d) " fmt, __FUNCTION__, __LINE__, ##args);	\
} while (0)

#undef dprintf
#define dprintf(fmt, args...)						\
do {									\
	if (debug)							\
		eprintf(fmt, args);					\
} while (0)

#define BUFSIZE 4096

static char program_name[] = "tgtadm";
static int debug;

static char *tgtadm_emsg[] = {
	"",
	"unknown error",
	"out of memory",
	"can't find the driver",
	"can't find the target", /* 5 */

	"can't find the logical unit",
	"can't find the session",
	"can't find the connection",
	"this target already exists",
	"this logical unit already exists",  /* 10 */

	"this access control rule already exists",
	"unknown parameter",
};

static struct option const long_options[] =
{
	{"lld", required_argument, NULL, 'l'},
	{"op", required_argument, NULL, 'o'},
	{"mode", required_argument, NULL, 'm'},
	{"tid", required_argument, NULL, 't'},
	{"sid", required_argument, NULL, 's'},
	{"cid", required_argument, NULL, 'c'},
	{"lun", required_argument, NULL, 'u'},
	{"aid", required_argument, NULL, 'a'},
	{"hostno", required_argument, NULL, 'i'},
	{"bus", required_argument, NULL, 'B'},
	{"name", required_argument, NULL, 'n'},
	{"value", required_argument, NULL, 'v'},
	{"targetname", required_argument, NULL, 'T'},
	{"initiator-address", required_argument, NULL, 'I'},
	{"target-type", required_argument, NULL, 'p'},
	{"backing-store", required_argument, NULL, 'b'},
	{"backing-store-type", required_argument, NULL, 'S'},
	{"debug", no_argument, NULL, 'd'},
	{"help", no_argument, NULL, 'h'},
	{NULL, 0, NULL, 0},
};

static char *short_options = "l:o:m:t:s:c:u:i:a:B:T:I:p:b:S:n:v:dh";

static void usage(int status)
{
	if (status != 0)
		fprintf(stderr, "Try `%s --help' for more information.\n", program_name);
	else {
		printf("Usage: %s [OPTION]\n", program_name);
		printf("\
Linux SCSI Target Framework Administration Utility.\n\
\n\
  --op create --tid=[id] --params [name]\n\
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
		eprintf("can't create a socket, %m\n");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_LOCAL;
	memcpy((char *) &addr.sun_path + 1, TGT_IPC_NAMESPACE,
	       strlen(TGT_IPC_NAMESPACE));

	err = connect(*fd, (struct sockaddr *) &addr, sizeof(addr));
	if (err < 0) {
		eprintf("can't connect to tgtd, %m\n");
		return -1;
	}

	return 0;
}

static int ipc_mgmt_rsp(int fd)
{
	struct tgtadm_rsp rsp;
	int err, rest, len;

	err = read(fd, &rsp, sizeof(rsp));
	if (err < 0) {
		eprintf("can't get the response, %m\n");
		return -1;
	}

	if (rsp.err != TGTADM_SUCCESS) {
		fprintf(stderr, "%s: %s\n", program_name, tgtadm_emsg[rsp.err]);
		return -1;
	}

	rest = rsp.len - sizeof(rsp);
	if (!rest)
		return 0;

	while (rest) {
		char buf[BUFSIZE];
		memset(buf, 0, sizeof(buf));
		len = min_t(int, sizeof(buf) - 1, rest);
		err = read(fd, buf, len);
		if (err <= 0) {
			eprintf("can't get the full response, %m\n");
			return -1;
		}
		fputs(buf, stdout);
		rest -= len;
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
		eprintf("can't send to tgtd, %m\n");
		goto out;
	}

	dprintf("sent to tgtd %d\n", err);

	err = ipc_mgmt_rsp(fd);
out:
	if (fd > 0)
		close(fd);
	return err;
}

static int filter(const struct dirent *dir)
{
	return strcmp(dir->d_name, ".") && strcmp(dir->d_name, "..");
}

static int bus_to_host(char *bus)
{
	int i, nr, host = -1;
	char path[PATH_MAX], *p;
	char key[] = "host";
	struct dirent **namelist;

	p = strchr(bus, ',');
	if (!p)
		return -EINVAL;
	*(p++) = '\0';

	snprintf(path, sizeof(path), "/sys/bus/%s/devices/%s", bus, p);
	nr = scandir(path, &namelist, filter, alphasort);
	if (!nr)
		return -ENOENT;

	for (i = 0; i < nr; i++) {
		if (strncmp(namelist[i]->d_name, key, strlen(key)))
			continue;
		p = namelist[i]->d_name + strlen(key);
		host = strtoull(p, NULL, 10);
	}

	for (i = 0; i < nr; i++)
		free(namelist[i]);
	free(namelist);

	return host;
}

static int backing_store_type(char *str)
{
	if (!strcmp(str, "file"))
		return LU_BS_FILE;
	else if (!strcmp(str, "raw"))
		return LU_BS_RAW;
	else
		return -1;
}

static int target_type(char *str)
{
	if (!strcmp(str, "disk"))
		return TARGET_SBC;
	else if (!strcmp(str, "tape"))
		return TARGET_SSC;
	else if (!strcmp(str, "cd"))
		return TARGET_MMC;
	else if (!strcmp(str, "osd"))
		return TARGET_OSD;
	else
		return -1;
}

static int str_to_mode(char *str)
{
	int mode;

	if (!strcmp("target", str) || !strcmp("tgt", str))
		mode = MODE_TARGET;
	else if (!strcmp("logicalunit", str) || !strcmp("lu", str))
		mode = MODE_DEVICE;
	else if (!strcmp("session", str) || !strcmp("sess", str))
		mode = MODE_SESSION;
	else if (!strcmp("connection", str) || !strcmp("conn", str))
		mode = MODE_CONNECTION;
	else if (!strcmp("account", str))
		mode = MODE_ACCOUNT;
	else
		mode = -1;

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
	else if (!strcmp("unbind", str))
		op = OP_UNBIND;
	else if (!strcmp("show", str))
		op = OP_SHOW;
	else if (!strcmp("update", str))
		op = OP_UPDATE;
	else
		op = -1;

	return op;
}

int main(int argc, char **argv)
{
	int ch, longindex;
	int err = -EINVAL, op = -1, len = 0;
	int tid = -1, rest = BUFSIZE;
	int t_type = TARGET_SBC, bs_type = LU_BS_FILE;
	uint32_t cid, hostno, aid;
	uint64_t sid, lun;
	char *lldname;
	struct tgtadm_req *req;
	char buf[BUFSIZE + sizeof(*req)];
	char *name, *value, *path, *targetname, *params, *address;
	int mode = MODE_SYSTEM;

	cid = hostno = aid = sid = lun = 0;
	lldname = name = value = path = targetname = address = NULL;

	optind = 1;
	while ((ch = getopt_long(argc, argv, short_options,
				 long_options, &longindex)) >= 0) {
		switch (ch) {
		case 'l':
			lldname = optarg;
			break;
		case 'o':
			op = str_to_op(optarg);
			break;
		case 'm':
			mode = str_to_mode(optarg);
			break;
		case 't':
			tid = strtol(optarg, NULL, 10);
			break;
		case 's':
			sid = strtoull(optarg, NULL, 10);
			break;
		case 'c':
			cid = strtoul(optarg, NULL, 10);
			break;
		case 'u':
			lun = strtoull(optarg, NULL, 10);
			break;
		case 'a':
			aid = strtol(optarg, NULL, 10);
			break;
		case 'i':
			hostno = strtol(optarg, NULL, 10);
			break;
		case 'B':
			hostno = bus_to_host(optarg);
			break;
		case 'T':
			targetname = optarg;
			break;
		case 'I':
			address = optarg;
			break;
		case 'p':
			t_type = target_type(optarg);
			break;
		case 'b':
			path = optarg;
			break;
		case 'S':
			bs_type = backing_store_type(optarg);
			break;
		case 'n':
			name = optarg;
			break;
		case 'v':
			value = optarg;
			break;
		case 'd':
			debug = 1;
			break;
		case 'h':
			usage(0);
			break;
		default:
			usage(1);
		}
	}
	if (op < 0) {
		eprintf("You must specify the operation type\n");
		goto out;
	}

	if (optind < argc) {
		fprintf(stderr, "unrecognized options: ");
		while (optind < argc)
			fprintf(stderr, "%s", argv[optind++]);
		fprintf(stderr, "\n");
		usage(1);
	}

	if (mode < 0) {
		fprintf(stderr, "unknown mode\n");
		usage(1);
	}

	memset(buf, 0, sizeof(buf));

	req = (struct tgtadm_req *) buf;
	if (lldname)
		strncpy(req->lld, lldname, sizeof(req->lld));
	req->mode = mode;
	req->op = op;
	req->tid = tid;
	req->sid = sid;
	req->lun = lun;
	req->aid = aid;
	req->host_no = hostno;

	params = buf + sizeof(*req);

	/* FIXME */
	if ((name && value) || path || targetname || address) {
		if (path) {
			name = "path";
			value = path;
		}

		if (targetname) {
			name = "targetname";
			value = targetname;
		}

		if (address) {
			name = "initiator-address";
			value = address;
		}

		len = snprintf(params, rest, "%s=%s", name, value);
	}

	if (t_type != TARGET_SBC)
		len += snprintf(params + len, rest - len,
				"%starget-type=%d", len ? "," : "", t_type);

	if (bs_type != LU_BS_FILE)
		len += snprintf(params + len, rest - len,
				"%sbacking-store-type=%d", len ? "," : "", bs_type);

	req->len = sizeof(*req) + len;

	err = ipc_mgmt_req(req);
out:
	return err;
}
