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
#include <poll.h>
#include <signal.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <asm/types.h>
#include <sys/signal.h>
#include <sys/stat.h>

#include "list.h"
#include "tgtd.h"
#include "driver.h"

enum {
	POLL_KI, /* kernel interface */
	POLL_IPC, /* unix domain socket for tgtdadm */
	POLL_END,
};

static char program_name[] = "tgtd";

static struct option const long_options[] =
{
	{"lld", required_argument, 0, 'l'},
	{"foreground", no_argument, 0, 'f'},
	{"debug", required_argument, 0, 'd'},
	{"version", no_argument, 0, 'v'},
	{"help", no_argument, 0, 'h'},
	{0, 0, 0, 0},
};

static void usage(int status)
{
	if (status)
		fprintf(stderr, "Try `%s --help' for more information.\n", program_name);
	else {
		printf("Usage: %s [OPTION]\n", program_name);
		printf("\
Target framework daemon.\n\
  -l, --lld               specify low level drivers to run\n\
  -f, --foreground        make the program run in the foreground\n\
  -d, --debug debuglevel  print debugging information\n\
  -h, --help              display this help and exit\n\
");
	}
	exit(1);
}

static void signal_catch(int signo) {
}

static int daemonize(void)
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

static void oom_adjust(void)
{
	int fd;
	char path[64];

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

static void event_loop(struct pollfd *pfd, int npfd, int timeout)
{
	int nevent, i;
	struct tgt_driver *d;

retry:
	/*
	 * TODO: replace something efficient than poll.
	 */
	nevent = poll(pfd, npfd, timeout);
	if (nevent < 0) {
		if (errno != EINTR) {
			eprintf("%s\n", strerror(errno));
			exit(1);
		}
		goto retry;
	} else if (nevent == 0) {
		/*
		 * TODO: need kinda scheduling stuff like open-iscsi here.
		 */
		goto retry;
	}

	if (pfd[POLL_KI].revents) {
		kspace_event_handle();
		nevent--;
	}

	if (pfd[POLL_IPC].revents) {
		dprintf("ipc event\n");
		ipc_event_handle(pfd[POLL_IPC].fd);
		nevent--;
	}

	if (!nevent)
		goto retry;

	for (i = 0; tgt_drivers[i]; i++) {
		dprintf("lld event\n");
		d = tgt_drivers[i];
		d->event_handle(pfd + d->pfd_index);
	}

	goto retry;
}

static struct pollfd *pfd_init(int npfd, int nl_fd, int ud_fd)
{
	struct tgt_driver *d;
	struct pollfd *pfd;
	int i, idx = POLL_END;

	pfd = calloc(npfd, sizeof(struct pollfd));
	if (!pfd)
		return NULL;

	pfd[POLL_KI].fd = nl_fd;
	pfd[POLL_KI].events = POLLIN;
	pfd[POLL_IPC].fd = ud_fd;
	pfd[POLL_IPC].events = POLLIN;

	for (i = 0; tgt_drivers[i]; i++) {
		d = tgt_drivers[i];
		if (d->enable && d->npfd) {
			d->pfd_index = idx;
			d->poll_init(pfd + idx);
			idx += d->npfd;
		}
	}

	return pfd;
}

static int lld_init(char *data, int *npfd)
{
	char *list, *p, *q;
	int index, err, np, ndriver = 0;

	p = list = strdup(data);
	if (!p)
		return 0;

	while (p) {
		q = strchr(p, ',');
		if (q)
			*q++ = '\0';
		index = get_driver_index(p);
		p = q;
		if (index >= 0) {
			np = 0;
			if (tgt_drivers[index]->init) {
				err = tgt_drivers[index]->init(&np);
				if (err)
					continue;
			}
			tgt_drivers[index]->enable = 1;
			tgt_drivers[index]->npfd = np;
			ndriver++;
			*npfd += np;
		}
	}
	free(list);

	return ndriver;
}

int main(int argc, char **argv)
{
	struct pollfd *pfd;
	struct sigaction sa_old;
	struct sigaction sa_new;
	int err, ch, longindex, nr_lld = 0, nr_pfd = POLL_END;
	int is_daemon = 1, is_debug = 1;
	int ki_fd, ipc_fd, timeout = -1;

	/* do not allow ctrl-c for now... */
	sa_new.sa_handler = signal_catch;
	sigemptyset(&sa_new.sa_mask);
	sa_new.sa_flags = 0;
	sigaction(SIGINT, &sa_new, &sa_old );
	sigaction(SIGPIPE, &sa_new, &sa_old );
	sigaction(SIGTERM, &sa_new, &sa_old );

	while ((ch = getopt_long(argc, argv, "l:fd:vh", long_options,
				 &longindex)) >= 0) {
		switch (ch) {
		case 'l':
			nr_lld = lld_init(optarg, &nr_pfd);
			break;
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

	if (!nr_lld) {
		printf("No available low level driver!\n");
		exit(1);
	}

	if (is_daemon && daemonize())
		exit(1);

	oom_adjust();

	err = log_init(program_name, LOG_SPACE_SIZE, is_daemon, is_debug);
	if (err)
		exit(1);

	err = kreq_init(&ki_fd);
	if (err)
		exit(1);

	err = ipc_init(&ipc_fd);
	if (err)
		exit(1);

	pfd = pfd_init(nr_pfd, ki_fd, ipc_fd);

	event_loop(pfd, nr_pfd, timeout);

	return 0;
}
