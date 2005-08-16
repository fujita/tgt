/*
 * ietadm - manage iSCSI Enterprise Target software.
 *
 * (C) 2004 - 2005 FUJITA Tomonori <tomof@acm.org>
 *
 * This code is licenced under the GPL.
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>

#include "iscsid.h"
#include "ietadm.h"

#define	SET_TARGET	(1 << 0)
#define	SET_SESSION	(1 << 1)
#define	SET_CONNECTION	(1 << 2)
#define	SET_LUNIT	(1 << 3)
#define	SET_USER	(1 << 4)

enum ietadm_op {
	OP_NEW,
	OP_DELETE,
	OP_UPDATE,
	OP_SHOW,
};

static char program_name[] = "ietadm";

static struct option const long_options[] =
{
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
iSCSI Enterprise Target Administration Utility.\n\
\n\
  --op new --tid=[id] --params Name=[name]\n\
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
                        change iSCSI IET target parameters of specific\n\
                        target with [id]. You can use parameters in ietd.conf\n\
                        as a key.\n\
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
Report bugs to <iscsitarget-devel@sourceforge.net>.\n");
	}
	exit(status == 0 ? 0 : -1);
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

static int ietd_request_send(int fd, struct ietadm_req *req)
{
	int err;

	if ((err = write(fd, req, sizeof(*req))) != sizeof(*req)) {
		fprintf(stderr, "%s %d %d\n", __FUNCTION__, __LINE__, err);
		if (err >= 0)
			err = -EIO;
	}
	return err;
}

static int ietd_response_recv(int fd)
{
	int err;
	struct ietadm_rsp rsp;

	if ((err = read(fd, &rsp, sizeof(rsp))) != sizeof(rsp)) {
		fprintf(stderr, "%s %d %d\n", __FUNCTION__, __LINE__, err);
		if (err >= 0)
			err = -EIO;
	} else
		err = rsp.err;

	return err;
}

static int ietd_connect(void)
{
	int fd, err;
	struct sockaddr_un addr;

	fd = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (fd < 0)
		return fd;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_LOCAL;
	memcpy((char *) &addr.sun_path + 1, IETADM_NAMESPACE, strlen(IETADM_NAMESPACE));

	if ((err = connect(fd, (struct sockaddr *) &addr, sizeof(addr))) < 0)
		fd = err;

	return fd;
}

static int ietd_request(struct ietadm_req *req)
{
	int fd = -1, err = -EIO;

	if ((fd = ietd_connect()) < 0) {
		err = fd;
		goto out;
	}

	if ((err = ietd_request_send(fd, req)) < 0)
		goto out;

	err = ietd_response_recv(fd);

out:
	if (fd > 0)
		close(fd);

	if (err < 0)
		fprintf(stderr, "%s %d %d %d\n", __FUNCTION__, __LINE__, req->rcmnd, err);
	return err;
}

static int parse_trgt_params(struct msg_trgt *msg, char *params)
{
	char *p, *q;

	while ((p = strsep(&params, ",")) != NULL) {
		int idx;
		u32 val;
		if (!*p)
			continue;
		if (!(q = strchr(p, '=')))
			continue;
		*q++ = '\0';
		val = strtol(q, NULL, 0);

		if (!((idx = param_index_by_name(p, target_keys)) < 0)) {
			if (!param_check_val(target_keys, idx, &val))
				msg->target_partial |= (1 << idx);
			msg->target_param[idx].val = val;
			msg->type |= 1 << key_target;

			continue;
		}

		if (!((idx = param_index_by_name(p, session_keys)) < 0)) {
			if (!param_check_val(session_keys, idx, &val))
				msg->session_partial |= (1 << idx);
			msg->session_param[idx].val = val;
			msg->type |= 1 << key_session;
		}
	}

	return 0;
}

static int trgt_handle(int op, u32 set, u32 tid, char *params)
{
	int err = -EINVAL;
	struct ietadm_req req;

	if (!(set & SET_TARGET))
		goto out;

	memset(&req, 0, sizeof(req));
	req.tid = tid;

	switch (op) {
	case OP_NEW:
	{
		char *p = params;

		if (!params || !(p = strchr(params, '=')))
			goto out;
		*p++ = '\0';
		if (strcmp(params, "Name"))
			goto out;
		req.rcmnd = C_TRGT_NEW;
		strncpy(req.u.trgt.name, p, sizeof(req.u.trgt.name) - 1);
		break;
	}
	case OP_DELETE:
		req.rcmnd = C_TRGT_DEL;
		break;
	case OP_UPDATE:
		req.rcmnd = C_TRGT_UPDATE;
		if ((err = parse_trgt_params(&req.u.trgt, params)) < 0)
			goto out;
		break;
	case OP_SHOW:
		req.rcmnd = C_TRGT_SHOW;
		break;
	}

	err = ietd_request(&req);

out:
	return err;
}

static int lunit_handle(int op, u32 set, u32 tid, u32 lun, char *params)
{
	int err = -EINVAL;
	struct ietadm_req req;

	if (op == OP_UPDATE) {
		fprintf(stderr, "Unsupported.\n");
		goto out;
	}

	if (!(set & SET_TARGET))
		goto out;

	memset(&req, 0, sizeof(req));
	req.tid = tid;
	req.lun = lun;

	switch (op) {
	case OP_NEW:
		req.rcmnd = C_LUNIT_NEW;
		strncpy(req.u.lunit.args, params, sizeof(req.u.lunit.args) - 1);
		break;
	case OP_DELETE:
		req.rcmnd = C_LUNIT_DEL;
		break;
	case OP_SHOW:
		req.rcmnd = C_LUNIT_SHOW;
		/* TODO */
		break;
	}

	err = ietd_request(&req);
out:
	return err;
}

static int sess_handle(int op, u32 set, u32 tid, u64 sid, char *params)
{
	int err = -EINVAL;

	if (op == OP_NEW || op == OP_UPDATE) {
		fprintf(stderr, "Unsupported.\n");
		goto out;
	}

	if (!((set & SET_TARGET) && (set & SET_SESSION)))
		goto out;

	switch (op) {
	case OP_DELETE:
		/* close all connections */
		break;
	case OP_SHOW:
		/* TODO */
		break;
	}

out:
	return err;
}

static int user_handle(int op, u32 set, u32 tid, char *params)
{
	int err = -EINVAL;
	char *p, *q, *user = NULL, *pass = NULL;
	struct ietadm_req req;

	if (set & ~(SET_TARGET | SET_USER))
		goto out;

	memset(&req, 0, sizeof(req));
	req.tid = tid;

	switch (op) {
	case OP_NEW:
		req.rcmnd = C_ACCT_NEW;
		break;
	case OP_DELETE:
		req.rcmnd = C_ACCT_DEL;
		break;
	case OP_UPDATE:
	case OP_SHOW:
		fprintf(stderr, "Unsupported.\n");
		goto out;
	}

	while ((p = strsep(&params, ",")) != NULL) {
		if (!*p)
			continue;

		if (!(q = strchr(p, '=')))
			continue;
		*q++ = '\0';
		if (isspace(*q))
			q++;

		if (!strcasecmp(p, "IncomingUser")) {
			if (user)
				fprintf(stderr, "Already specified user %s\n", q);
			user = q;
			req.u.acnt.auth_dir = AUTH_DIR_INCOMING;
		} else if (!strcasecmp(p, "OutgoingUser")) {
			if (user)
				fprintf(stderr, "Already specified user %s\n", q);
			user = q;
			req.u.acnt.auth_dir = AUTH_DIR_OUTGOING;
		} else if (!strcasecmp(p, "Password")) {
			if (pass)
				fprintf(stderr, "Already specified pass %s\n", q);
			pass = q;
		} else {
			fprintf(stderr, "Unknown parameter %p\n", q);
			goto out;
		}
	}

	if ((op == OP_NEW && ((user && !pass) || (!user && pass) || (!user && !pass))) ||
	    (op == OP_DELETE && ((!user && pass) || (!user && !pass)))) {
		fprintf(stderr,
			"You need to specify a user and its password %s %s\n", pass, user);
		goto out;
	}

	strncpy(req.u.acnt.user, user, sizeof(req.u.acnt.user) - 1);
	if (pass)
		strncpy(req.u.acnt.pass, pass, sizeof(req.u.acnt.pass) - 1);

	err = ietd_request(&req);
out:
	return err;
}

static int conn_handle(int op, u32 set, u32 tid, u64 sid, u32 cid, char *params)
{
	int err = -EINVAL;
	struct ietadm_req req;

	if (op == OP_NEW || op == OP_UPDATE) {
		fprintf(stderr, "Unsupported.\n");
		goto out;
	}

	if (!((set & SET_TARGET) && (set & SET_SESSION) && (set & SET_CONNECTION)))
		goto out;

	memset(&req, 0, sizeof(req));
	req.tid = tid;
	req.sid = sid;
	req.cid = cid;

	switch (op) {
	case OP_DELETE:
		req.rcmnd = C_CONN_DEL;
		break;
	case OP_SHOW:
		req.rcmnd = C_CONN_SHOW;
		/* TODO */
		break;
	}

	err = ietd_request(&req);
out:
	return err;
}

static int sys_handle(int op, u32 set, char *params)
{
	int err = -EINVAL;
	struct ietadm_req req;

	memset(&req, 0, sizeof(req));

	switch (op) {
	case OP_NEW:
		break;
	case OP_DELETE:
		req.rcmnd = C_SYS_DEL;
		break;
	case OP_UPDATE:
		break;
	case OP_SHOW:
		break;
	}

	err = ietd_request(&req);

	return err;
}

int main(int argc, char **argv)
{
	int ch, longindex;
	int err = -EINVAL, op = -1;
	u32 tid = 0, cid = 0, lun = 0, set = 0;
	u64 sid = 0;
	char *params = NULL;

	while ((ch = getopt_long(argc, argv, "o:t:s:c:l:p:uvh",
				 long_options, &longindex)) >= 0) {
		switch (ch) {
		case 'o':
			op = str_to_op(optarg);
			break;
		case 't':
			tid = strtoul(optarg, NULL, 10);
			set |= SET_TARGET;
			break;
		case 's':
			sid = strtoull(optarg, NULL, 10);
			set |= SET_SESSION;
			break;
		case 'c':
			cid = strtoul(optarg, NULL, 10);
			set |= SET_CONNECTION;
			break;
		case 'l':
			lun = strtoul(optarg, NULL, 10);
			set |= SET_LUNIT;
			break;
		case 'p':
			params = optarg;
			break;
		case 'u':
			set |= SET_USER;
			break;
		case 'v':
			printf("%s version %s\n", program_name, IET_VERSION_STRING);
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
		fprintf(stderr, "You must specify the operation type\n");
		goto out;
	}

	if (optind < argc) {
		fprintf(stderr, "unrecognized: ");
		while (optind < argc)
			fprintf(stderr, "%s", argv[optind++]);
		fprintf(stderr, "\n");
		usage(-1);
	}

	if (set & SET_USER)
		err = user_handle(op, set, tid, params);
	else if (set & SET_LUNIT)
		err = lunit_handle(op, set, tid, lun, params);
	else if (set & SET_CONNECTION)
		err = conn_handle(op, set, tid, sid, cid, params);
	else if (set & SET_SESSION)
		err = sess_handle(op, set, tid, sid, params);
	else if (set & SET_TARGET)
		err = trgt_handle(op, set, tid, params);
	else if (!set)
		err = sys_handle(op, set, params);
	else
		usage(-1);

out:
	return err;
}
