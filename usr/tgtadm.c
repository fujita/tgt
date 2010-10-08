/*
 * SCSI target daemon management interface
 *
 * Copyright (C) 2005-2007 FUJITA Tomonori <tomof@acm.org>
 * Copyright (C) 2005-2007 Mike Christie <michaelc@cs.wisc.edu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
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

#include "scsi.h"
#include "util.h"
#include "list.h"
#include "tgtadm.h"

#define NO_LOGGING
#include "log.h"

#define BUFSIZE 4096

static char program_name[] = "tgtadm";
static int debug;

static const char * tgtadm_strerror(int err)
{
	static const struct {
		enum tgtadm_errno err;
		char *desc;
	} errors[] = {
		{ TGTADM_SUCCESS, "success" },
		{ TGTADM_UNKNOWN_ERR, "unknown error" },
		{ TGTADM_NOMEM, "out of memory" },
		{ TGTADM_NO_DRIVER, "can't find the driver" },
		{ TGTADM_NO_TARGET, "can't find the target" },
		{ TGTADM_NO_LUN, "can't find the logical unit" },
		{ TGTADM_NO_SESSION, "can't find the session" },
		{ TGTADM_NO_CONNECTION, "can't find the connection" },
		{ TGTADM_TARGET_EXIST, "this target already exists" },
		{ TGTADM_LUN_EXIST, "this logical unit number already exists" },
		{ TGTADM_ACL_EXIST, "this access control rule already exists" },
		{ TGTADM_USER_EXIST, "this account already exists" },
		{ TGTADM_NO_USER, "can't find the account" },
		{ TGTADM_TOO_MANY_USER, "too many accounts" },
		{ TGTADM_INVALID_REQUEST, "invalid request" },
		{ TGTADM_OUTACCOUNT_EXIST,
		  "this target already has an outgoing account" },
		{ TGTADM_TARGET_ACTIVE, "this target is still active" },
		{ TGTADM_LUN_ACTIVE, "this logical unit is still active" },
		{ TGTADM_UNSUPPORTED_OPERATION,
		  "this operation isn't supported" },
		{ TGTADM_UNKNOWN_PARAM, "unknown parameter" }
	};
	int i;

	for (i = 0; i < ARRAY_SIZE(errors); ++i)
		if (errors[i].err == err)
			return errors[i].desc;

	return "(unknown tgtadm_errno)";
}

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
	{"bstype", required_argument, NULL, 'E'},
	{"bsoflags", required_argument, NULL, 'f'},
	{"targetname", required_argument, NULL, 'T'},
	{"initiator-address", required_argument, NULL, 'I'},
	{"user", required_argument, NULL, 'u'},
	{"password", required_argument, NULL, 'p'},
	{"host", required_argument, NULL, 'H'},
	{"params", required_argument, NULL, 'P'},

	{"bus", required_argument, NULL, 'B'},
	{"device-type", required_argument, NULL, 'Y'},
	{"outgoing", no_argument, NULL, 'O'},
	{"control-port", required_argument, NULL, 'C'},
	{NULL, 0, NULL, 0},
};

static char *short_options = "dhL:o:m:t:s:c:l:n:v:b:E:f:T:I:u:p:H:P:B:Y:O:C:";

static void usage(int status)
{
	if (status != 0)
		fprintf(stderr, "Try `%s --help' for more information.\n", program_name);
	else {
		printf("Usage: %s [OPTION]\n", program_name);
		printf("\
Linux SCSI Target Framework Administration Utility, version %s\n\
\n\
  --lld <driver> --mode target --op new --tid <id> --targetname <name>\n\
                        add a new target with <id> and <name>. <id> must not be zero.\n\
  --lld <driver> --mode target --op delete --tid <id>\n\
                        delete the specific target with <id>. The target must\n\
                        have no activity.\n\
  --lld <driver> --mode target --op show\n\
                        show all the targets.\n\
  --lld <driver> --mode target --op show --tid <id>\n\
                        show the specific target's parameters.\n\
  --lld <driver> --mode target --op update --tid <id> --name <param> --value <value>\n\
                        change the target parameters of the specific\n\
                        target with <id>.\n\
  --lld <driver> --mode target --op bind --tid <id> --initiator-address <src>\n\
                        enable the target to accept the specific initiators.\n\
  --lld <driver> --mode target --op unbind --tid <id> --initiator-address <src>\n\
                        disable the specific permitted initiators.\n\
  --lld <driver> --mode logicalunit --op new --tid <id> --lun <lun> \\\n\
                        --backing-store <path> --bstype <type> --bsoflags <options>\n\
                        add a new logical unit with <lun> to the specific\n\
                        target with <id>. The logical unit is offered\n\
                        to the initiators. <path> must be block device files\n\
                        (including LVM and RAID devices) or regular files.\n\
                        bstype option is optional.\n\
                        bsoflags supported options are sync and direct\n\
                        (sync:direct for both).\n\
  --lld <driver> --mode logicalunit --op delete --tid <id> --lun <lun>\n\
                        delete the specific logical unit with <lun> that\n\
                        the target with <id> has.\n\
  --lld <driver> --mode account --op new --user <name> --password <pass>\n\
                        add a new account with <name> and <pass>.\n\
  --lld <driver> --mode account --op delete --user <name>\n\
                        delete the specific account having <name>.\n\
  --lld <driver> --mode account --op bind --tid <id> --user <name> [--outgoing]\n\
                        add the specific account having <name> to\n\
                        the specific target with <id>.\n\
                        <user> could be <IncomingUser> or <OutgoingUser>.\n\
                        If you use --outgoing option, the account will\n\
                        be added as an outgoing account.\n\
  --lld <driver> --mode account --op unbind --tid <id> --user <name>\n\
                        delete the specific account having <name> from specific\n\
                        target.\n\
  --control-port <port> use control port <port>\n\
  --help                display this help and exit\n\
\n\
Report bugs to <stgt@vger.kernel.org>.\n", TGT_VERSION);
	}
	exit(status == 0 ? 0 : EINVAL);
}

/* default port to use for the mgmt channel */
static short int control_port = 0;

static int ipc_mgmt_connect(int *fd)
{
	int err;
	struct sockaddr_un addr;
	char path[256];

	*fd = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (*fd < 0) {
		eprintf("can't create a socket, %m\n");
		return errno;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_LOCAL;
	sprintf(path, "%s.%d", TGT_IPC_NAMESPACE, control_port);
	strncpy(addr.sun_path, path, sizeof(addr.sun_path));

	err = connect(*fd, (struct sockaddr *) &addr, sizeof(addr));
	if (err < 0)
		return errno;

	return 0;
}

static int ipc_mgmt_rsp(int fd, struct tgtadm_req *req)
{
	struct tgtadm_rsp rsp;
	int err, rest, len;

retry:
	err = recv(fd, &rsp, sizeof(rsp), MSG_WAITALL);
	if (err < 0) {
		if (errno == EAGAIN)
			goto retry;
		else if (errno == EINTR)
			eprintf("interrupted by a signal\n");
		else
			eprintf("can't get the response, %m\n");

		return errno;
	} else if (err == 0) {
		eprintf("tgtd closed the socket\n");
		return 0;
	} else if (err != sizeof(rsp)) {
		eprintf("a partial response\n");
		return 0;
	}

	if (rsp.err != TGTADM_SUCCESS) {
		eprintf("%s\n",	tgtadm_strerror(rsp.err));
		return EINVAL;
	}

	if (req->mode == MODE_SYSTEM && req->op == OP_DELETE) {
		while (1) {
			int __fd, ret;
			struct timeval tv;

			ret = ipc_mgmt_connect(&__fd);
			if (ret == ECONNREFUSED)
				break;

			close(__fd);

			tv.tv_sec = 0;
			tv.tv_usec = 100 * 1000;

			select(0, NULL, NULL, NULL, &tv);
		}
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
	if (err < 0) {
		eprintf("can't connect to the tgt daemon, %m\n");
		goto out;
	}

	err = write(fd, (char *) req, req->len);
	if (err < 0) {
		eprintf("can't send the request to the tgt daemon, %m\n");
		err = errno;
		goto out;
	}

	dprintf("sent to tgtd %d\n", err);

	err = ipc_mgmt_rsp(fd, req);
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

static int str_to_device_type(char *str)
{
	if (!strcmp(str, "disk"))
		return TYPE_DISK;
	else if (!strcmp(str, "tape"))
		return TYPE_TAPE;
	else if (!strcmp(str, "cd"))
		return TYPE_MMC;
	else if (!strcmp(str, "changer"))
		return TYPE_MEDIUM_CHANGER;
	else if (!strcmp(str, "osd"))
		return TYPE_OSD;
	else if (!strcmp(str, "ssc"))
		return TYPE_TAPE;
	else if (!strcmp(str, "pt"))
		return TYPE_PT;
	else {
		eprintf("unknown target type: %s\n", str);
		exit(EINVAL);
	}
}

static int str_to_mode(char *str)
{
	if (!strcmp("system", str) || !strcmp("sys", str))
		return MODE_SYSTEM;
	else if (!strcmp("target", str) || !strcmp("tgt", str))
		return MODE_TARGET;
	else if (!strcmp("logicalunit", str) || !strcmp("lu", str))
		return MODE_DEVICE;
	else if (!strcmp("session", str) || !strcmp("sess", str))
		return MODE_SESSION;
	else if (!strcmp("connection", str) || !strcmp("conn", str))
		return MODE_CONNECTION;
	else if (!strcmp("account", str))
		return MODE_ACCOUNT;
	else if (!strcmp("stats", str))
		return MODE_STATS;
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

static int verify_mode_params(int argc, char **argv, char *allowed)
{
	int ch, longindex;
	int ret = 0;

	optind = 0;

	while ((ch = getopt_long(argc, argv, short_options,
				 long_options, &longindex)) >= 0) {
		if (!strchr(allowed, ch) && !strchr("d", ch)) {
			ret = ch;
			break;
		}
	}

	return ret;
}

int main(int argc, char **argv)
{
	int ch, longindex, rc;
	int op, total, tid, rest, mode, dev_type, ac_dir;
	uint32_t cid, hostno;
	uint64_t sid, lun;
	char *name, *value, *path, *targetname, *params, *address, *targetOps;
	char *bstype;
	char *bsoflags;
	char *user, *password;
	char *buf;
	size_t bufsz = BUFSIZE + sizeof(struct tgtadm_req);
	struct tgtadm_req *req;

	op = tid = mode = -1;
	total = cid = hostno = sid = 0;
	lun = UINT64_MAX;

	rc = 0;
	dev_type = TYPE_DISK;
	ac_dir = ACCOUNT_TYPE_INCOMING;
	rest = BUFSIZE;
	name = value = path = targetname = address = targetOps = bstype = NULL;
	bsoflags = user = password = NULL;

	buf = valloc(bufsz);
	if (!buf) {
		eprintf("%s\n",	tgtadm_strerror(TGTADM_NOMEM));
		return ENOMEM;
	}

	memset(buf, 0, bufsz);
	req = (struct tgtadm_req *) buf;

	optind = 1;
	while ((ch = getopt_long(argc, argv, short_options,
				 long_options, &longindex)) >= 0) {
		errno = 0;
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
			if (errno == EINVAL) {
				eprintf("invalid tid '%s'\n", optarg);
				exit(EINVAL);
			}
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
		case 'P':
			targetOps = optarg;
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
		case 'H':
			hostno = strtol(optarg, NULL, 10);
			break;
		case 'f':
			bsoflags = optarg;
			break;
		case 'E':
			bstype = optarg;
			break;
		case 'Y':
			dev_type = str_to_device_type(optarg);
			break;
		case 'O':
			ac_dir = ACCOUNT_TYPE_OUTGOING;
			break;
		case 'C':
			control_port = strtol(optarg, NULL, 10);
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
		eprintf("unrecognized option '%s'\n", argv[optind]);
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

	if (mode == MODE_SYSTEM) {
		switch (op) {
		case OP_UPDATE:
			rc = verify_mode_params(argc, argv, "LmonvC");
			if (rc) {
				eprintf("system mode: option '-%c' is not "
					"allowed/supported\n", rc);
				exit(EINVAL);
			}
			if ((!name || !value)) {
				eprintf("update operation requires 'name'"
					" and 'value' options\n");
				exit(EINVAL);
			}
			break;
		case OP_SHOW:
		case OP_DELETE:
			break;
		default:
			eprintf("option %d not supported in system mode\n", op);
			exit(EINVAL);
			break;
		}
	}

	if (mode == MODE_TARGET) {
		if ((tid <= 0 && (op != OP_SHOW))) {
			eprintf("'tid' option is necessary\n");
			exit(EINVAL);
		}
		switch (op) {
		case OP_NEW:
			rc = verify_mode_params(argc, argv, "LmotTC");
			if (rc) {
				eprintf("target mode: option '-%c' is not "
					  "allowed/supported\n", rc);
				exit(EINVAL);
			}
			if (!targetname) {
				eprintf("creating a new target requires name\n");
				exit(EINVAL);
			}
			break;
		case OP_DELETE:
		case OP_SHOW:
			rc = verify_mode_params(argc, argv, "LmotC");
			if (rc) {
				eprintf("target mode: option '-%c' is not "
					  "allowed/supported\n", rc);
				exit(EINVAL);
			}
			break;
		case OP_BIND:
		case OP_UNBIND:
			rc = verify_mode_params(argc, argv, "LmotIBHC");
			if (rc) {
				eprintf("target mode: option '-%c' is not "
					  "allowed/supported\n", rc);
				exit(EINVAL);
			}
			if (!address && !hostno) {
				eprintf("%s operation requires"
					" initiator-address or bus\n",
					op == OP_BIND ? "bind" : "unbind");
				exit(EINVAL);
			}
			break;
		case OP_UPDATE:
			rc = verify_mode_params(argc, argv, "LmotnvC");
			if (rc) {
				eprintf("target mode: option '-%c' is not "
					  "allowed/supported\n", rc);
				exit(EINVAL);
			}
			if ((!name || !value)) {
				eprintf("update operation requires 'name'"
						" and 'value' options\n");
				exit(EINVAL);
			}
			break;
		default:
			eprintf("option %d not supported in target mode\n", op);
			exit(EINVAL);
			break;
		}
	}

	if (mode == MODE_ACCOUNT) {
		switch (op) {
		case OP_NEW:
			rc = verify_mode_params(argc, argv, "LmoupfC");
			if (rc) {
				eprintf("logicalunit mode: option '-%c' is not "
					  "allowed/supported\n", rc);
				exit(EINVAL);
			}
			if (!user || !password) {
				eprintf("'user' and 'password' options is necessary\n");
				exit(EINVAL);
			}
			break;
		case OP_SHOW:
			rc = verify_mode_params(argc, argv, "LmoC");
			if (rc) {
				eprintf("target mode: option '-%c' is not "
					  "allowed/supported\n", rc);
				exit(EINVAL);
			}
			break;
		case OP_DELETE:
			rc = verify_mode_params(argc, argv, "LmouC");
			if (rc) {
				eprintf("target mode: option '-%c' is not "
					  "allowed/supported\n", rc);
				exit(EINVAL);
			}
			break;
		case OP_BIND:
			rc = verify_mode_params(argc, argv, "LmotuOC");
			if (rc) {
				eprintf("target mode: option '-%c' is not "
					  "allowed/supported\n", rc);
				exit(EINVAL);
			}
			if (!user) {
				eprintf("'user' option is necessary\n");
				exit(EINVAL);
			}
			if (tid == -1)
				tid = GLOBAL_TID;
			break;
		case OP_UNBIND:
			rc = verify_mode_params(argc, argv, "LmotuC");
			if (rc) {
				eprintf("target mode: option '-%c' is not "
					  "allowed/supported\n", rc);
				exit(EINVAL);
			}
			if (!user) {
				eprintf("'user' option is necessary\n");
				exit(EINVAL);
			}
			if (tid == -1)
				tid = GLOBAL_TID;
			break;
		default:
			eprintf("option %d not supported in account mode\n", op);
			exit(EINVAL);
			break;
		}
	}

	if (mode == MODE_DEVICE) {
		if (tid <= 0) {
			eprintf("'tid' option is necessary\n");
			exit(EINVAL);
		}
		if (lun == UINT64_MAX) {
			eprintf("'lun' option is necessary\n");
			exit(EINVAL);
		}
		switch (op) {
		case OP_NEW:
			rc = verify_mode_params(argc, argv, "LmoftlbEYC");
			if (rc) {
				eprintf("target mode: option '-%c' is not "
					  "allowed/supported\n", rc);
				exit(EINVAL);
			}
			if (!path) {
				eprintf("'backing-store' option "
						"is necessary\n");
				exit(EINVAL);
			}
			break;
		case OP_DELETE:
			rc = verify_mode_params(argc, argv, "LmotlC");
			if (rc) {
				eprintf("target mode: option '-%c' is not "
					  "allowed/supported\n", rc);
				exit(EINVAL);
			}
			break;
		case OP_UPDATE:
			rc = verify_mode_params(argc, argv, "LmoftlPC");
			if (rc) {
				eprintf("option '-%c' not supported in "
					"logicalunit mode\n", rc);
				exit(EINVAL);
			}
			break;
		default:
			eprintf("option %d not supported in "
					"logicalunit mode\n", op);
			exit(EINVAL);
			break;
		}
	}

	req->op = op;
	req->tid = tid;
	req->sid = sid;
	req->cid = cid;
	req->lun = lun;
	req->mode = mode;
	req->host_no = hostno;
	req->device_type = dev_type;
	req->ac_dir = ac_dir;

	params = buf + sizeof(*req);

	if (name)
		shprintf(total, params, rest, "%s=%s", name, value);
	if (path)
		shprintf(total, params, rest, "%spath=%s",
			 rest == BUFSIZE ? "" : ",", path);

	if (req->device_type == TYPE_TAPE)
		shprintf(total, params, rest, "%sbstype=%s",
			 rest == BUFSIZE ? "" : ",", "ssc");
	else if (bstype)
		shprintf(total, params, rest, "%sbstype=%s",
			 rest == BUFSIZE ? "" : ",", bstype);
	if (bsoflags)
		shprintf(total, params, rest, "%sbsoflags=%s",
			 rest == BUFSIZE ? "" : ",", bsoflags);
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
	/* Trailing ',' makes parsing params in modules easier.. */
	if (targetOps)
		shprintf(total, params, rest, "%stargetOps %s,",
			 rest == BUFSIZE ? "" : ",", targetOps);

	req->len = sizeof(*req) + total;

	return ipc_mgmt_req(req);
overflow:
	eprintf("BUFSIZE (%d bytes) isn't long enough\n", BUFSIZE);
	return EINVAL;
}
