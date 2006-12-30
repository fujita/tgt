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
#include "tgtadm.h"

#undef eprintf
#define eprintf(fmt, args...)						\
do {									\
	fprintf(stderr, "%s: " fmt, program_name, ##args);		\
} while (0)

#undef dprintf
#define dprintf(fmt, args...)						\
do {									\
	if (debug)							\
		fprintf(stderr, "%s %d: " fmt,				\
			__FUNCTION__, __LINE__, ##args);		\
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
	"this account already exists",
	"can't find the account",
	"Too many accounts",
	"invalid request", /* 15 */

	"this target already has an outgoing account",
	"unknown parameter",
};

struct option const long_options[] = {
	{"debug", no_argument, NULL, 'd'},
	{"help", no_argument, NULL, 'h'},
	{"lld", required_argument, NULL, 'L'},
	{"op", required_argument, NULL, 'o'},
	{"mode", required_argument, NULL, 'm'},
	{"tid", required_argument, NULL, 't'},
	{"sid", required_argument, NULL, 's'},
	{"cid", required_argument, NULL, 'c'},
	{"lun", required_argument, NULL, 'l'},
	{"name", required_argument, NULL, 'n'},
	{"value", required_argument, NULL, 'v'},
	{"backing-store", required_argument, NULL, 'b'},
	{"targetname", required_argument, NULL, 'T'},
	{"initiator-address", required_argument, NULL, 'I'},
	{"user", required_argument, NULL, 'u'},
	{"password", required_argument, NULL, 'p'},

	{"bus", required_argument, NULL, 'B'},
	{"target-type", required_argument, NULL, 'Y'},
	{"backing-store-type", required_argument, NULL, 'S'},
	{"outgoing", no_argument, NULL, 'O'},
	{NULL, 0, NULL, 0},
};

static char *short_options = "dhL:o:m:t:s:c:l:n:v:b:T:I:u:p:";

static void usage(int status)
{
	if (status != 0)
		fprintf(stderr, "Try `%s --help' for more information.\n", program_name);
	else {
		printf("Usage: %s [OPTION]\n", program_name);
		printf("\
Linux SCSI Target Framework Administration Utility.\n\
\n\
  --lld [driver] --mode target --op new --tid=[id] --targetname [name]\n\
                        add a new target with [id] and [name]. [id] must not be zero.\n\
  --lld [driver] --mode target --op delete --tid=[id]\n\
                        delete the specific target with [id]. The target must\n\
                        have no activity.\n\
  --lld [driver] --mode target --op show\n\
                        show all the targets.\n\
  --lld [driver] --mode target --op show --tid=[id]\n\
                        show the specific target's parameters.\n\
  --lld [driver] --mode target --op update --tid=[id] --name=[param] --value=[value]\n\
                        change the target parameters of the specific\n\
                        target with [id].\n\
  --lld [driver] --mode target --op bind --tid=[id] --initiator-address=[src]\n\
                        enable the target to accept the specific initiators.\n\
  --lld [driver] --mode target --op unbind --tid=[id] --initiator-address=[src]\n\
                        disable the specific permitted initiators.\n\
  --lld [driver] --mode logicalunit --op new --tid=[id] --lun=[lun] --backing-store=[path]\n\
                        add a new logical unit with [lun] to the specific\n\
                        target with [id]. The logical unit is offered\n\
                        to the initiators. [path] must be block device files\n\
                        (including LVM and RAID devices) or regular files.\n\
  --lld [driver] --mode logicalunit --op delete --tid=[id] --lun=[lun]\n\
                        delete the specific logical unit with [lun] that\n\
                        the target with [id] has.\n\
  --lld [driver] --mode account --op new --user=[name] --password=[pass]\n\
                        add a new account with [name] and [pass].\n\
  --lld [driver] --mode account --op delete --user=[name]\n\
                        delete the specific account having [name].\n\
  --lld [driver] --mode account --op bind --tid=[id] --user=[name] [--outgoing]\n\
                        add the specific account having [name] to\n\
                        the specific target with [id].\n\
                        [user] could be [IncomingUser] or [OutgoingUser].\n\
                        If you use --outgoing option, the account will\n\
                        be added as an outgoing account.\n\
  --lld [driver] --mode account --op unbind --tid=[id] --user=[name]\n\
                        delete the specific account having [name] from specific\n\
                        target.\n\
  --help                display this help and exit\n\
\n\
Report bugs to <stgt-devel@lists.berlios.de>.\n");
	}
	exit(status == 0 ? 0 : EINVAL);
}

static int ipc_mgmt_connect(int *fd)
{
	int err;
	struct sockaddr_un addr;

	*fd = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (*fd < 0) {
		eprintf("can't create a socket, %m\n");
		return errno;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_LOCAL;
	memcpy((char *) &addr.sun_path + 1, TGT_IPC_NAMESPACE,
	       strlen(TGT_IPC_NAMESPACE));

	err = connect(*fd, (struct sockaddr *) &addr, sizeof(addr));
	if (err < 0) {
		eprintf("can't connect to the tgt daemon, %m\n");
		return errno;
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
		return errno;
	}

	if (rsp.err != TGTADM_SUCCESS) {
		eprintf("%s\n", tgtadm_emsg[rsp.err]);
		return EINVAL;
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
			eprintf("\ncan't get the full response, %m\n");
			return errno;
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
		eprintf("can't send the request to the tgt daemon, %m\n");
		err = errno;
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

	if (host == -1) {
		eprintf("can't find bus: %s\n", bus);
		exit(EINVAL);
	}
	return host;
}

static int backing_store_type(char *str)
{
	if (!strcmp(str, "file"))
		return LU_BS_FILE;
	else if (!strcmp(str, "raw"))
		return LU_BS_RAW;
	else {
		eprintf("unknown backing store type: %s\n", str);
		exit(EINVAL);
	}
}

static int target_type(char *str)
{
	if (!strcmp(str, "disk"))
		return TARGET_SBC;
	else if (!strcmp(str, "tape")) {
		eprintf("type emulation isn't supported yet\n");
		exit(EINVAL);
	} else if (!strcmp(str, "cd")) {
		eprintf("cdrom emulation isn't supported yet\n");
		exit(EINVAL);
	} else if (!strcmp(str, "osd")) {
		eprintf("osd isn't supported yet\n");
		exit(EINVAL);
	} else {
		eprintf("unknown target type: %s\n", str);
		exit(EINVAL);
	}
}

static int str_to_mode(char *str)
{
	if (!strcmp("target", str) || !strcmp("tgt", str))
		return MODE_TARGET;
	else if (!strcmp("logicalunit", str) || !strcmp("lu", str))
		return MODE_DEVICE;
	else if (!strcmp("session", str) || !strcmp("sess", str))
		return MODE_SESSION;
	else if (!strcmp("connection", str) || !strcmp("conn", str))
		return MODE_CONNECTION;
	else if (!strcmp("account", str))
		return MODE_ACCOUNT;
	else {
		eprintf("unknown mode: %s\n", str);
		exit(1);
	}
}

static int str_to_op(char *str)
{
	if (!strcmp("new", str))
		return OP_NEW;
	else if (!strcmp("delete", str))
		return OP_DELETE;
	else if (!strcmp("bind", str))
		return OP_BIND;
	else if (!strcmp("unbind", str))
		return OP_UNBIND;
	else if (!strcmp("show", str))
		return OP_SHOW;
	else if (!strcmp("update", str))
		return OP_UPDATE;
	else {
		eprintf("unknown operation: %s\n", str);
		exit(1);
	}
}

int main(int argc, char **argv)
{
	int ch, longindex;
	int op, total, tid, rest, mode, t_type, bs_type, ac_dir;
	uint32_t cid, hostno;
	uint64_t sid, lun;
	char *name, *value, *path, *targetname, *params, *address;
	char *user, *password;
	char buf[BUFSIZE + sizeof(struct tgtadm_req)];
	struct tgtadm_req *req;

	op = tid = mode = -1;
	total = cid = hostno = sid = lun = 0;
	t_type = TARGET_SBC;
	bs_type = LU_BS_FILE;
	ac_dir = ACCOUNT_TYPE_INCOMING;
	rest = BUFSIZE;
	name = value = path = targetname = address = NULL;
	user = password = NULL;

	memset(buf, 0, sizeof(buf));
	req = (struct tgtadm_req *) buf;

	optind = 1;
	while ((ch = getopt_long(argc, argv, short_options,
				 long_options, &longindex)) >= 0) {
		switch (ch) {
		case 'L':
			strncpy(req->lld, optarg, sizeof(req->lld));
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
		case 'l':
			lun = strtoull(optarg, NULL, 10);
			break;
		case 'n':
			name = optarg;
			break;
		case 'v':
			value = optarg;
			break;
		case 'b':
			path = optarg;
			break;
		case 'T':
			targetname = optarg;
			break;
		case 'I':
			address = optarg;
			break;
		case 'u':
			user = optarg;
			break;
		case 'p':
			password = optarg;
			break;
		case 'B':
			hostno = bus_to_host(optarg);
			break;
		case 'Y':
			t_type = target_type(optarg);
			break;
		case 'S':
			bs_type = backing_store_type(optarg);
			break;
		case 'O':
			ac_dir = ACCOUNT_TYPE_OUTGOING;
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

	if (optind < argc) {
		eprintf("unrecognized options: ");
		while (optind < argc)
			eprintf("%s", argv[optind++]);
		eprintf("\n");
		usage(1);
	}

	if (op < 0) {
		eprintf("specify the operation type\n");
		exit(EINVAL);
	}

	if (mode < 0) {
		eprintf("specify the mode\n");
		exit(EINVAL);
	}

	if (!*req->lld) {
		eprintf("specify the low level driver name\n");
		exit(EINVAL);
	}

	if ((name || value) && op != OP_UPDATE) {
		eprintf("only 'update' operation takes"
			" 'name' and 'value' options\n");
		exit(EINVAL);
	}

	if ((!name && value) || (name && !value)) {
		eprintf("'name' and 'value' options are necessary\n");
		exit(EINVAL);
	}

	if (mode == MODE_TARGET) {
		switch (op) {
		case OP_NEW:
		case OP_DELETE:
		case OP_BIND:
		case OP_UNBIND:
		case OP_UPDATE:
			if (op == OP_NEW && !targetname) {
				eprintf("creating a new target needs the name\n");
				exit(EINVAL);
			}

			if (tid < 0) {
				eprintf("'tid' option is necessary\n");
				exit(EINVAL);
			}
			break;
		default:
			break;
		}
	}

	if (mode == MODE_DEVICE) {
		switch (op) {
		case OP_NEW:
			if (!path) {
				eprintf("the backing store path is necessary\n");
				exit(EINVAL);
			}
			break;
		default:
			break;
		}
	}

	if (mode == MODE_ACCOUNT) {
		switch (op) {
		case OP_NEW:
			if (!user || !password) {
				eprintf("'user' and 'password' options is necessary\n");
				exit(EINVAL);
			}
			break;
		case OP_SHOW:
			break;
		case OP_DELETE:
		case OP_BIND:
		case OP_UNBIND:
			if (!user) {
				eprintf("'user' option is necessary\n");
				exit(EINVAL);
			}

			if ((op == OP_BIND || op == OP_UNBIND) && tid < 0) {
				eprintf("'tid' option is necessary\n");
				exit(EINVAL);
			}
			break;
		default:
			eprintf("the update operation can't"
				" handle accounts\n");
			exit(EINVAL);
			break;
		}
	}

	req->op = op;
	req->tid = tid;
	req->sid = sid;
	req->lun = lun;
	req->mode = mode;
	req->host_no = hostno;
	req->target_type = t_type;
	req->bs_type = bs_type;
	req->ac_dir = ac_dir;

	params = buf + sizeof(*req);

	if (name)
		shprintf(total, params, rest, "%s=%s", name, value);
	if (path)
		shprintf(total, params, rest, "%spath=%s",
			 rest == BUFSIZE ? "" : ",", path);
	if (targetname)
		shprintf(total, params, rest, "%stargetname=%s",
			 rest == BUFSIZE ? "" : ",", targetname);
	if (address)
		shprintf(total, params, rest, "%sinitiator-address=%s",
			 rest == BUFSIZE ? "" : ",", address);
	if (user)
		shprintf(total, params, rest, "%suser=%s",
			 rest == BUFSIZE ? "" : ",", user);
	if (password)
		shprintf(total, params, rest, "%spassword=%s",
			 rest == BUFSIZE ? "" : ",", password);

	req->len = sizeof(*req) + total;

	return ipc_mgmt_req(req);
overflow:
	eprintf("BUFSIZE (%d bytes) isn't long enough\n", BUFSIZE);
	return EINVAL;
}
