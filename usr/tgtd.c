/*
 * SCSI target daemon
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
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <signal.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <asm/types.h>
#include <sys/poll.h>
#include <sys/signal.h>
#include <sys/stat.h>
#include <scsi/scsi_tgt_if.h>

#include "tgtd.h"

extern int tgt_sysfs_init(void);

enum {
	POLL_NL, /* netlink socket between kernel and user space */
	POLL_UD, /* unix domain socket for tgtdadm */
};

static struct option const long_options[] =
{
	{"foreground", no_argument, 0, 'f'},
	{"debug", required_argument, 0, 'd'},
	{"version", no_argument, 0, 'v'},
	{"help", no_argument, 0, 'h'},
	{0, 0, 0, 0},
};

static char program_name[] = "tgtd";

static int daemon_init(void)
{
	pid_t pid;

	pid = fork();
	if (pid < 0)
		return -ENOMEM;
	else if (pid)
		exit(0);

	setsid();
	chdir("/");
	close(0);
	open("/dev/null", O_RDWR);
	dup2(0, 1);
	dup2(0, 2);

	return 0;
}

static void usage(int status)
{
	if (status != 0)
		fprintf(stderr, "Try `%s --help' for more information.\n", program_name);
	else {
		printf("Usage: %s [OPTION]\n", program_name);
		printf("\
Target framework daemon.\n\
  -f, --foreground        make the program run in the foreground\n\
  -d, --debug debuglevel  print debugging information\n\
  -h, --help              display this help and exit\n\
");
	}
	exit(1);
}

static void signal_catch(int signo) {
}

static void tgtd_init(void)
{
	int fd;
	char path[64];
	struct sigaction sa_old;
	struct sigaction sa_new;

	/* do not allow ctrl-c for now... */
	sa_new.sa_handler = signal_catch;
	sigemptyset(&sa_new.sa_mask);
	sa_new.sa_flags = 0;
	sigaction(SIGINT, &sa_new, &sa_old );
	sigaction(SIGPIPE, &sa_new, &sa_old );
	sigaction(SIGTERM, &sa_new, &sa_old );

	/* Should we use RT stuff? */
	nice(-20);

	/* Avoid oom-killer */
	sprintf(path, "/proc/%d/oom_adj", getpid());
	fd = open(path, O_WRONLY);
	if (fd < 0) {
		fprintf(stderr, "can not adjust oom-killer's pardon %s\n", path);
		return;
	}
	write(fd, "-17\n", 4);
	close(fd);
}

/* TODO: rewrite makeshift poll code */

static void event_loop(struct driver_info *dlinfo, struct pollfd *pfd, int nr_dls)
{
	int err, i, poll_max = (nr_dls + 1) * POLLS_PER_DRV;
	void (* fn)(struct pollfd *, int);

	while (1) {
		if ((err = poll(pfd, poll_max, -1)) < 0) {
			if (errno != EINTR) {
				eprintf("%d %d\n", err, errno);
				exit(1);
			}
			continue;
		}

		if (pfd[POLL_NL].revents) {
			nl_event_handle(pfd[POLL_NL].fd);
			err--;
		}

		if (pfd[POLL_UD].revents) {
			ipc_event_handle(dlinfo, pfd[POLL_UD].fd);
			err--;
		}

		if (!err)
			continue;

		for (i = 0; i < nr_dls; i++) {
			fn = dl_fn(dlinfo, i, DL_FN_POLL_EVENT);
			if (fn)
				fn(pfd + ((i + 1) * POLLS_PER_DRV), POLLS_PER_DRV);
		}
	}
}

static struct pollfd * poll_init(int nr, int nl_fd, int ud_fd)
{
	struct pollfd *pfd;
	void (* fn)(struct pollfd *, int);
	int i;

	pfd = calloc((nr + 1) * POLLS_PER_DRV, sizeof(struct pollfd));
	if (!pfd) {
		eprintf("Out of memory\n");
		exit(1);
	}

	pfd[POLL_NL].fd = nl_fd;
	pfd[POLL_NL].events = POLLIN;
	pfd[POLL_UD].fd = ud_fd;
	pfd[POLL_UD].events = POLLIN;

	for (i = 0; i < nr; i++) {
		fn = dl_fn(dlinfo, i, DL_FN_POLL_INIT);
		if (fn)
			fn(pfd + (i + 1) * POLLS_PER_DRV, POLLS_PER_DRV);
	}

	return pfd;
}

int main(int argc, char **argv)
{
	struct pollfd *pfd;
	int ch, longindex, nr;
	int is_daemon = 1, is_debug = 1;
	int nl_fd, ud_fd;

	while ((ch = getopt_long(argc, argv, "fd:vh", long_options,
				 &longindex)) >= 0) {
		switch (ch) {
		case 'f':
			is_daemon = 0;
			break;
		case 'd':
			is_debug = atoi(optarg);
			break;
		case 'v':
			exit(0);
			break;
		case 'h':
			usage(0);
			break;
		default:
			usage(1);
			break;
		}
	}

	if (is_daemon && daemon_init())
		exit(1);

	tgtd_init();

	if (log_init(program_name, LOG_SPACE_SIZE, is_daemon, is_debug))
		exit(1);

	if (tgt_sysfs_init())
		exit(1);

	nl_fd = nl_init();
	if (nl_fd < 0)
		exit(1);

	ud_fd = ipc_open();
	if (ud_fd < 0)
		exit(1);

	nr = dl_init(dlinfo);
	if (nr < nr)
		exit(1);

	pfd = poll_init(nr, nl_fd, ud_fd);

	event_loop(dlinfo, pfd, nr);

	return 0;
}
