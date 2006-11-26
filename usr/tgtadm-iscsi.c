/*
 * iSCSI target management interface
 *
 * Copyright (C) 2006 FUJITA Tomonori <tomof@acm.org>
 * Copyright (C) 2006 Mike Christie <michaelc@cs.wisc.edu>
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

#include "util.h"
#include "list.h"
#include "tgtd.h"
#include "tgtadm.h"
#include "driver.h"

/*
 * This program is just a wrapper of tgtadm. Maybe it would be better
 * to implement this program by using Python or Perl.
 */

static char cmdstr[] = "tgtadm --lld iscsi";
static char cmdline[2048];

static struct option const long_options[] =
{
	{"op", required_argument, NULL, 'o'},
	{"tid", required_argument, NULL, 't'},
	{"sid", required_argument, NULL, 's'},
	{"cid", required_argument, NULL, 'c'},
	{"lun", required_argument, NULL, 'u'},
	{"aid", required_argument, NULL, 'a'},
	{"iqn", required_argument, NULL, 'i'},
	{"path", required_argument, NULL, 'p'},
	{"name", required_argument, NULL, 'n'},
	{"value", required_argument, NULL, 'v'},
	{"start", no_argument, NULL, 'S'},
	{"stop", no_argument, NULL, 'P'},
	{"user", required_argument, NULL, 'r'},
	{"password", required_argument, NULL, 'w'},
	{"in", no_argument, NULL, 'I'},
	{"out", no_argument, NULL, 'O'},
	{"debug", no_argument, NULL, 'd'},
	{"help", no_argument, NULL, 'h'},
	{NULL, 0, NULL, 0},
};

static char *short_options = "o:t:s:c:u:a:n:i:p:v:SPr:w:IOdh";

static void usage(int status)
{
}

static int target_op(int op, int tid, char *iqn, char *name, char *value,
		     int start, int stop)
{
	int err = -EINVAL;
	FILE *fp;

	if (start && stop) {
		fprintf(stderr,
			"Cannot start and stop a target at the same time\n");
		exit(1);
	}

	if (start || stop)
		op = OP_UPDATE;

	switch (op) {
	case OP_NEW:
		if (!iqn) {
			fprintf(stderr, "specifiy target's iqn\n");
			exit(1);
		}

		snprintf(cmdline, sizeof(cmdline), "%s -o new -m tgt -t %d",
			 cmdstr, tid);
		fp = popen(cmdline, "r");
		if (!fp) {
			fprintf(stderr, "fail to exec %s\n", cmdstr);
			exit(1);
		}

		err = pclose(fp);
		if (err) {
			fprintf(stderr, "fail to create a new target\n");
			exit(1);
		}

		snprintf(cmdline, sizeof(cmdline), "%s -o update -m tgt -t %d"
			 " -n iqn -v %s", cmdstr, tid, iqn);
		fp = popen(cmdline, "r");
		if (!fp) {
			fprintf(stderr, "fail to exec %s\n", cmdstr);
			exit(1);
			/* remove the target. */
		}

		err = pclose(fp);
		if (err) {
			fprintf(stderr, "fail to create a new target\n");
			exit(1);
			/* remove the target. */
		}
		break;
	case OP_SHOW:
		if (tid == -1)
			snprintf(cmdline, sizeof(cmdline), "%s -o show -m tgt",
				 cmdstr);
		else
			snprintf(cmdline, sizeof(cmdline),
				 "%s -o show -m tgt -t %d", cmdstr, tid);
		fp = popen(cmdline, "r");
		if (!fp) {
			fprintf(stderr, "fail to exec %s\n", cmdstr);
			exit(1);
		}

		while (fgets(cmdline, sizeof(cmdline), fp))
			fputs(cmdline, stdout);

		err = pclose(fp);

		break;
	case OP_UPDATE:
		if (start || stop)
			snprintf(cmdline, sizeof(cmdline),
				 "%s -o update -m tgt -t %d -n state -v %s",
				 cmdstr, tid, start ? "running" : "suspended");
		else
			snprintf(cmdline, sizeof(cmdline),
				 "%s -o update -m tgt -t %d -n %s -v %s",
				 cmdstr, tid, name, value);
		fp = popen(cmdline, "r");
		if (!fp) {
			fprintf(stderr, "fail to exec %s\n", cmdstr);
			exit(1);
		}

		err = pclose(fp);
		if (err) {
			fprintf(stderr, "fail to change the state\n");
			exit(1);
		}
		break;
	default:
		break;
	}

	return err;
}

static int session_op(int op, int tid, uint64_t sid, char *name, char *value)
{
	int err = -EINVAL;
	FILE *fp;

	switch (op) {
	case OP_SHOW:
		if (sid)
			snprintf(cmdline, sizeof(cmdline),
				 "%s -o show -m sess -t %d -s %" PRIu64,
				 cmdstr, tid, sid);
		else
			snprintf(cmdline, sizeof(cmdline),
				 "%s -o show -m sess -t %d", cmdstr, tid);
		fp = popen(cmdline, "r");
		if (!fp) {
			fprintf(stderr, "fail to exec %s\n", cmdstr);
			exit(1);
		}

		while (fgets(cmdline, sizeof(cmdline), fp))
			fputs(cmdline, stdout);

		err = pclose(fp);
		break;
	default:
		break;
	}

	return err;
}

static int logicalunit_op(int op, int tid, uint64_t lun, char *path,
			  char *name, char *value)
{
	int err = -EINVAL;
	FILE *fp;

	switch (op) {
	case OP_NEW:
		if (!path) {
			fprintf(stderr, "specifiy logical unit's path\n");
			exit(1);
		}

		snprintf(cmdline, sizeof(cmdline), "%s -o new -m lu -t %d -u %" PRIu64,
			 cmdstr, tid, lun);
		fp = popen(cmdline, "r");
		if (!fp) {
			fprintf(stderr, "fail to exec %s\n", cmdstr);
			exit(1);
		}

		err = pclose(fp);
		if (err) {
			fprintf(stderr, "fail to create a logical unit\n");
			exit(1);
			/* remove the lu. */
		}

		snprintf(cmdline, sizeof(cmdline), "%s -o update -m lu -t %d -u %" PRIu64
			 " -n path -v %s", cmdstr, tid, lun, path);
		fp = popen(cmdline, "r");
		if (!fp) {
			fprintf(stderr, "fail to exec %s\n", cmdstr);
			exit(1);

			/* remove the lu */
		}

		err = pclose(fp);
		if (err) {
			fprintf(stderr, "fail to create a logical unit\n");
			exit(1);
			/* remove the lu. */
		}
		break;
	case OP_SHOW:
		snprintf(cmdline, sizeof(cmdline),
			 "%s -o show -m lu -t %d -u %" PRIu64,
			 cmdstr, tid, lun);
		fp = popen(cmdline, "r");
		if (!fp) {
			fprintf(stderr, "fail to exec %s\n", cmdstr);
			exit(1);
		}

		while (fgets(cmdline, sizeof(cmdline), fp))
			fputs(cmdline, stdout);

		err = pclose(fp);
		if (err) {
			fprintf(stderr, "fail to show a logical unit\n");
			exit(1);
			/* remove the lu. */
		}
	}

	return err;
}

static int account_op(int op, int tid, int in, int out, int aid,
		      char *user, char *password, char *name, char *value)
{
	int err = -EINVAL;
	FILE *fp;

	switch (op) {
	case OP_NEW:
		/* TODO: error handling */

		if ((!in && !out) || (in && out)) {
			fprintf(stderr, "specify incoming or outgoing\n");
			exit(1);
		}

		snprintf(cmdline, sizeof(cmdline), "%s -o new -m account -a %u",
			 cmdstr, aid);
		fp = popen(cmdline, "r");
		if (!fp) {
			fprintf(stderr, "fail to exec %s\n", cmdstr);
			exit(1);
		}

		err = pclose(fp);
		if (err) {
			fprintf(stderr, "fail to create a logical unit\n");
			exit(1);
		}

		snprintf(cmdline, sizeof(cmdline),
			 "%s -o update -m account -a %u -n User -v %s",
			 cmdstr, aid, user);

		fp = popen(cmdline, "r");
		if (!fp)
			exit(1);

		err = pclose(fp);
		if (err)
			exit(1);

		snprintf(cmdline, sizeof(cmdline),
			 "%s -o update -m account -a %u -n Password -v %s",
			 cmdstr, aid, password);
		fp = popen(cmdline, "r");
		if (!fp)
			exit(1);

		err = pclose(fp);
		if (err)
			exit(1);

		snprintf(cmdline, sizeof(cmdline),
			 "%s -o update -m account -a %u -n Type -v %s",
			 cmdstr, aid, in ? "Incoming" : "Outgoing");
		fp = popen(cmdline, "r");
		if (!fp)
			exit(1);

		err = pclose(fp);
		if (err)
			exit(1);

		snprintf(cmdline, sizeof(cmdline),
			 "%s -o bind -m account -t %d -a %u",
			 cmdstr, tid, aid);
		fp = popen(cmdline, "r");
		if (!fp)
			exit(1);

		err = pclose(fp);
		if (err)
			exit(1);
		break;
	case OP_SHOW:
		snprintf(cmdline, sizeof(cmdline), "%s -o show -m account -t %d",
			 cmdstr, tid);
		fp = popen(cmdline, "r");
		if (!fp) {
			fprintf(stderr, "fail to exec %s\n", cmdstr);
			exit(1);
		}

		while (fgets(cmdline, sizeof(cmdline), fp))
			fputs(cmdline, stdout);

		err = pclose(fp);
		if (err)
			exit(1);
	}

	return err;
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
	else if (!strcmp("update", str))
		op = OP_UPDATE;
	else
		op = -1;

	return op;
}

int main(int argc, char **argv)
{
	int ch, longindex;
	char *name, *value, *iqn, *path, *user, *password;
	int err = -EINVAL, op = -1, tid = -1, mode = 0;
	uint32_t cid, aid = 0;
	uint64_t sid = 0, lun = -1;
	int start, stop, in, out;

	start = stop = in = out = 0;
	name = value = iqn = path = user = password = NULL;

	while ((ch = getopt_long(argc, argv, short_options,
				 long_options, &longindex)) >= 0) {
		switch (ch) {
		case 'o':
			op = str_to_op(optarg);
			break;
		case 't':
			tid = strtol(optarg, NULL, 10);
			mode |= (1 << MODE_TARGET);
			break;
		case 's':
			sid = strtoull(optarg, NULL, 10);
			mode |= (1 << MODE_SESSION);
			break;
		case 'c':
			cid = strtoul(optarg, NULL, 10);
			mode |= (1 << MODE_CONNECTION);
			break;
		case 'u':
			lun = strtoull(optarg, NULL, 10);
			mode |= (1 << MODE_DEVICE);
			break;
		case 'a':
			aid = strtol(optarg, NULL, 10);
			mode |= (1 << MODE_ACCOUNT);
			break;
		case 'i':
			iqn = optarg;
			break;
		case 'p':
			path = optarg;
			break;
		case 'n':
			name = optarg;
			break;
		case 'v':
			value = optarg;
			break;
		case 'S':
			start = 1;
			break;
		case 'P':
			stop = 1;
			break;
		case 'r':
			user = optarg;
			break;
		case 'w':
			password = optarg;
			break;
		case 'I':
			in = 1;
			break;
		case 'O':
			out = 1;
			break;
		case 'h':
			usage(0);
			break;
		default:
			usage(-1);
		}
	}

	if (mode & (1 << MODE_ACCOUNT))
		account_op(op, tid, in, out, aid, user, password, name, value);
	else if (mode & (1 << MODE_DEVICE))
		err = logicalunit_op(op, tid, lun, path, name, value);
	else if (mode & (1 << MODE_CONNECTION))
		;
	else if (mode & (1 << MODE_SESSION))
		err = session_op(op, tid, sid, name, value);
	else
		err = target_op(op, tid, iqn, name, value, start, stop);

	return err;
}
