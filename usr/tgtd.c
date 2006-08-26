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
#include <sys/epoll.h>
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
#include "util.h"

#define MAX_FDS	4096

struct tgt_event {
	event_handler_t *handler;
	void *data;
	int fd;
	struct list_head e_list;
};

static int ep_fd;
static char program_name[] = "tgtd";
static LIST_HEAD(tgt_events_list);

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

int tgt_event_add(int fd, int events, event_handler_t handler, void *data)
{
	struct epoll_event ev;
	struct tgt_event *tev;
	int err;

	tev = malloc(sizeof(*tev));
	if (!tev)
		return -ENOMEM;

	tev->data = data;
	tev->handler = handler;
	tev->fd = fd;

	ev.events = events;
	ev.data.ptr = tev;
	err = epoll_ctl(ep_fd, EPOLL_CTL_ADD, fd, &ev);
	if (err)
		free(tev);
	else
		list_add(&tev->e_list, &tgt_events_list);

	return err;
}

void tgt_event_del(int fd)
{
	struct tgt_event *tev;

	epoll_ctl(ep_fd, EPOLL_CTL_DEL, fd, NULL);

	list_for_each_entry(tev, &tgt_events_list, e_list) {
		if (tev->fd == fd) {
			list_del(&tev->e_list);
			free(tev);
			break;
		}
	}
}

static void event_loop(int timeout)
{
	int nevent, i;
	struct epoll_event events[1024];
	struct tgt_event *tev;

retry:
	nevent = epoll_wait(ep_fd, events, ARRAY_SIZE(events), timeout);
	if (nevent < 0) {
		if (errno != EINTR) {
			eprintf("%m\n");
			exit(1);
		}
		goto retry;
	} else if (nevent == 0) {
		/*
		 * TODO: need kinda scheduling stuff like open-iscsi here.
		 */
		goto retry;
	}

	for (i = 0; i < nevent; i++) {
		tev = (struct tgt_event *) events[i].data.ptr;
		tev->handler(tev->fd, tev->data);
	}

	goto retry;
}

static int lld_init(char *data)
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
			ndriver++;
		}
	}
	free(list);

	return ndriver;
}

int main(int argc, char **argv)
{
	struct sigaction sa_old;
	struct sigaction sa_new;
	int err, ch, longindex, fd, nr_lld = 0, maxfds = MAX_FDS, timeout = -1;
	int is_daemon = 1, is_debug = 1;
	char *modes = NULL;

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
			modes = optarg;
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

	nr_lld = lld_init(modes);
	if (!nr_lld) {
		printf("No available low level driver!\n");
		exit(1);
	}

	if (is_daemon && daemon(0,0))
		exit(1);

	oom_adjust();

	err = log_init(program_name, LOG_SPACE_SIZE, is_daemon, is_debug);
	if (err)
		exit(1);

	ep_fd = epoll_create(maxfds);
	if (ep_fd < 0) {
		eprintf("can't create epoll fd, %m\n");
		exit(1);
	}

	err = kreq_init(&fd);
	if (err)
		eprintf("No kernel interface\n");
	else
		tgt_event_add(fd, POLL_IN, kern_event_handler, NULL);

	err = ipc_init(&fd);
	if (err)
		exit(1);
	else
		tgt_event_add(fd, POLL_IN, mgmt_event_handler, NULL);

	event_loop(timeout);

	return 0;
}
