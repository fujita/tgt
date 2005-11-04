/*
 * tgtadm - manage Target Framework software.
 *
 * (C) 2005 FUJITA Tomonori <tomof@acm.org>
 * (C) 2005 Mike Christie <michaelc@cs.wisc.edu>
 * This code is licenced under the GPL.
 */

/*
 * This is just taken from ietadm. Possibly, we need to redesign the
 * greater part of this to handle every target driver.
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
#include <linux/netlink.h>

#include "tgtadm.h"
#include "tgt_sysfs.h"

#define eprintf(fmt, args...)						\
do {									\
	fprintf(stderr, "%s(%d) " fmt, __FUNCTION__, __LINE__, ##args);	\
} while (0)

#define dprintf eprintf

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

static int filter(const struct dirent *dir)
{
	return strcmp(dir->d_name, ".") && strcmp(dir->d_name, "..");
}

static int driver_to_typeid(char *name)
{
	int i, nr, err, fd, id = -ENOENT;
	char *p, path[PATH_MAX], buf[PATH_MAX];
	struct dirent **namelist;

	nr = scandir(TGT_TYPE_SYSFSDIR, &namelist, filter, alphasort);
	for (i = 0; i < nr; i++) {
		snprintf(path, sizeof(path), TGT_TYPE_SYSFSDIR "/%s/name",
			 namelist[i]->d_name);

		fd = open(path, O_RDONLY);
		if (fd < 0) {
			eprintf("%s %d\n", path, errno);
			continue;
		}

		err = read(fd, buf, sizeof(buf));
		close(fd);
		if (err < 0) {
			eprintf("%s %d\n", path, err);
			continue;
		}

		if (strncmp(name, buf, strlen(name)))
			continue;

		for (p = namelist[i]->d_name; !isdigit((int) *p); p++)
			;
		id = atoi(p);
		break;
	}

	for (i = 0; i < nr; i++)
		free(namelist[i]);
	free(namelist);

	return id;
}

static int driver_dl_init(int argc, char **argv)
{
	int ch, longindex, id;
	char *name = NULL;

	while ((ch = getopt_long(argc, argv, "n:", long_options,
				 &longindex)) >= 0) {
		switch (ch) {
		case 'n':
			name = optarg;
			break;
		}
	}

	if (!name) {
		eprintf("You must specify the driver name\n");
		goto out;
	}

	id = driver_to_typeid(name);
	if (id < 0) {
		eprintf("Invalid driver name %s\n", name);
		goto out;
	}

	return id;
out:
	exit(0);
}

static int ipc_mgmt_connect(void)
{
	int fd, err;
	struct sockaddr_un addr;

	fd = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (fd < 0)
		return fd;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_LOCAL;
	memcpy((char *) &addr.sun_path + 1, TGT_IPC_NAMESPACE, strlen(TGT_IPC_NAMESPACE));

	err = connect(fd, (struct sockaddr *) &addr, sizeof(addr));
	if (err < 0)
		return err;

	return fd;
}

static void ipc_mgmt_result(char *rbuf)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *) rbuf;
	struct tgtadm_res *res = NLMSG_DATA(nlh);

	if (res->err < 0)
		fprintf(stderr, "%d\n", res->err);

	if (nlh->nlmsg_len > NLMSG_LENGTH(0))
		fprintf(stderr, "%s\n", (char *) res + sizeof(*res));
}

static int ipc_mgmt_call(char *data, int len, char *rbuf)
{
	int fd, err;
	char sbuf[8192];
	struct nlmsghdr *nlh = (struct nlmsghdr *) sbuf;
	struct iovec iov;
	struct msghdr msg;

	memset(sbuf, 0, sizeof(sbuf));
	memcpy(NLMSG_DATA(nlh), data, len);

	nlh->nlmsg_len = NLMSG_LENGTH(len);
	nlh->nlmsg_type = 0;
	nlh->nlmsg_flags = 0;
	nlh->nlmsg_pid = getpid();

	fd = ipc_mgmt_connect();
	if (fd < 0)
		return fd;

	err = write(fd, sbuf, nlh->nlmsg_len);
	if (err < 0)
		goto out;

	nlh = (struct nlmsghdr *) rbuf;
	iov.iov_base = nlh;
	iov.iov_len = NLMSG_ALIGN(nlh->nlmsg_len);
	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	err = recvmsg(fd, &msg, MSG_PEEK);
	if (err < 0)
		return err;

	iov.iov_base = nlh;
	iov.iov_len = NLMSG_ALIGN(nlh->nlmsg_len);
	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	err = recvmsg(fd, &msg, MSG_DONTWAIT);
	if (err < 0)
		return err;

out:
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
	else if (!strcmp("update", str))
		op = OP_UPDATE;
	else if (!strcmp("show", str))
		op = OP_SHOW;
	else
		op = -1;

	return op;
}

int main(int argc, char **argv)
{
	int ch, longindex;
	int err = -EINVAL, op = -1, len;
	int tid = -1, typeid;
	uint32_t cid = 0, set = 0;
	uint64_t sid = 0, lun = 0;
	char *params = NULL;
	struct tgtadm_req *req;
	char sbuf[8192], rbuf[8912];

	typeid = driver_dl_init(argc, argv);
	if (typeid < 0)
		goto out;

	optind = 1;
	while ((ch = getopt_long(argc, argv, "n:o:t:s:c:l:p:uvh",
				 long_options, &longindex)) >= 0) {
		switch (ch) {
		case 'n':
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

	memset(sbuf, 0, sizeof(sbuf));
	memset(rbuf, 0, sizeof(rbuf));

	req = (struct tgtadm_req *) sbuf;
	req->typeid = typeid;
	req->mode = set_to_mode(set);
	req->op = op;
	req->tid = tid;
	req->sid = sid;
	req->lun = lun;

	len = sizeof(struct tgtadm_req);
	if (params) {
		memcpy(sbuf + sizeof(struct tgtadm_req), params, strlen(params));
		len += strlen(params);
	}

	err = ipc_mgmt_call(sbuf, len, rbuf);
	ipc_mgmt_result(rbuf);
out:
	return err;
}
