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
#include <linux/types.h>
#include <linux/netlink.h>

#include "tgtadm.h"
#include "tgt_sysfs.h"

#define eprintf(fmt, args...)						\
do {									\
	fprintf(stderr, "%s(%d) " fmt, __FUNCTION__, __LINE__, ##args);	\
} while (0)

#define dprintf eprintf

static char program_name[] = "tgtadm";
static char *driver;

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
	{"bus", required_argument, NULL, 'b'},
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

static void all_devices_destroy(int tid)
{
	struct dirent **namelist;
	char path[PATH_MAX], key[] = "device";
	int i, nr, err;
	uint64_t dev_id;

	snprintf(path, sizeof(path), TGT_TARGET_SYSFSDIR "/target%d", tid);
	nr = scandir(path, &namelist, filter, alphasort);
	if (!nr)
		return;

	for (i = 0; i < nr; i++) {
		if (strncmp(namelist[i]->d_name, key, strlen(key)))
			continue;
		dev_id = strtoull(namelist[i]->d_name + strlen(key), NULL, 10);
		snprintf(path, sizeof(path),
			 "./usr/tgtadm --driver %s --op delete --tid %d --lun %"
			 PRIu64, driver, tid, dev_id);
		err = system(path);
	}

	for (i = 0; i < nr; i++)
		free(namelist[i]);
	free(namelist);
}

static int tid_to_hostno(int tid)
{
	int fd, hostno, err;
	char path[PATH_MAX], buf[32];

	snprintf(path, sizeof(path), TGT_TARGET_SYSFSDIR "/target%d/hostno", tid);
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		eprintf("Cannot open %s\n", path);
		return -EINVAL;
	}
	err = read(fd, buf, sizeof(buf));
	close(fd);
	if (err < 0) {
		eprintf("Cannot read\n");
		return -EINVAL;
	}

	sscanf(buf, "%d\n", &hostno);

	return hostno;
}

static int hostno_to_name(int hostno, char *buf, int len)
{
	int fd, err;
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "/sys/class/scsi_host/host%d/proc_name",
		 hostno);

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		eprintf("Cannot open %s\n", path);
		return -EINVAL;
	}
	err = read(fd, buf, len);
	close(fd);

	return strlen(buf);
}

static int system_mgmt(struct tgtadm_req *req, char *lld)
{
	int err = -EINVAL, i, nr, hostno;
	struct dirent **namelist;
	char cmd[PATH_MAX], buf[64], *p;

	if (req->op != OP_DELETE)
		return err;

	nr = scandir(TGT_TARGET_SYSFSDIR, &namelist, filter, alphasort);
	if (!nr)
		return -ENOENT;

	for (i = 0; i < nr; i++) {
		int tid;
		for (p = namelist[i]->d_name; !isdigit((int) *p); p++)
			;
		tid = atoi(p);
		hostno = tid_to_hostno(tid);
		if (hostno < 0)
			continue;
		hostno_to_name(hostno, buf, sizeof(buf));
		if (strcmp(buf, lld))
			continue;

		all_devices_destroy(tid);
		snprintf(cmd, sizeof(cmd),
			 "./usr/tgtadm --driver %s --op delete --tid %d",
			 lld, tid);
		err = system(cmd);
	}

	for (i = 0; i < nr; i++)
		free(namelist[i]);
	free(namelist);

	return 0;
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
	else if (!strcmp("bind", str))
		op = OP_BIND;
	else if (!strcmp("show", str))
		op = OP_SHOW;
	else
		op = -1;

	return op;
}

static int lldname_to_id(char *name)
{
	struct dirent **namelist;
	int i, nr, id = -EINVAL;
	char *p;

	nr = scandir(TGT_LLD_SYSFSDIR, &namelist, filter, alphasort);
	if (!nr)
		return -EINVAL;

	for (i = 0; i < nr; i++) {
		p = strchr(namelist[i]->d_name, '-');
		if (p && !strcmp(name, p + 1)) {
			*p='\0';
			id = atoi(namelist[i]->d_name);
			break;
		}
	}

	for (i = 0; i < nr; i++)
		free(namelist[i]);
	free(namelist);

	return id;
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

static int lld_id_get(int argc, char **argv)
{
	int ch, longindex, id = -EINVAL;
	char *name = NULL;

	while ((ch = getopt_long(argc, argv, "n:", long_options,
				 &longindex)) >= 0) {
		switch (ch) {
		case 'n':
			name = optarg;
			break;
		}
	}

	if (name)
		id = lldname_to_id(name);

	if (id < 0) {
		eprintf("You must specify the driver name\n");
		exit(-1);
	}

	return id;
}

int main(int argc, char **argv)
{
	int ch, longindex;
	int err = -EINVAL, op = -1, len;
	int tid = -1;
	uint32_t cid = 0, set = 0, hostno = 0, lld_id;
	uint64_t sid = 0, lun = 0;
	char *params = NULL, *lld_name = NULL;
	struct tgtadm_req *req;
	char sbuf[8192], rbuf[8912];

	lld_id = lld_id_get(argc, argv);
	if (lld_id < 0)
		goto out;

	optind = 1;
	while ((ch = getopt_long(argc, argv, "n:o:t:s:c:l:b:p:uvh",
				 long_options, &longindex)) >= 0) {
		switch (ch) {
		case 'n':
			lld_name = optarg;
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
			hostno = bus_to_host(optarg);
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
	req->typeid = lld_id;
	req->mode = set_to_mode(set);
	req->op = op;
	req->tid = tid;
	req->sid = sid;
	req->lun = lun;
	req->host_no = hostno;

	len = sizeof(struct tgtadm_req);
	if (params) {
		memcpy(sbuf + sizeof(struct tgtadm_req), params, strlen(params));
		len += strlen(params);
	}

	if (req->mode == MODE_SYSTEM)
		err = system_mgmt(req, lld_name);
	else {
		err = ipc_mgmt_call(sbuf, len, rbuf);
		ipc_mgmt_result(rbuf);
	}
out:
	return err;
}
