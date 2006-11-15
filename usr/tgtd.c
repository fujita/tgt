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
#include <libaio.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>

#include "list.h"
#include "tgtd.h"
#include "driver.h"
#include "sched.h"
#include "util.h"

#define MAX_FDS	4096

struct tgt_event {
	event_handler_t *handler;
	void *data;
	int fd;
	struct list_head e_list;
};

io_context_t ctx;

static int ep_fd;
static char program_name[] = "tgtd";
static LIST_HEAD(tgt_events_list);

static struct option const long_options[] =
{
	{"foreground", no_argument, 0, 'f'},
	{"debug", required_argument, 0, 'd'},
	{"help", no_argument, 0, 'h'},
	{0, 0, 0, 0},
};

static char *short_options = "fd:h";

static void usage(int status)
{
	if (status)
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
	exit(status);
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

	tev = zalloc(sizeof(*tev));
	if (!tev)
		return -ENOMEM;

	tev->data = data;
	tev->handler = handler;
	tev->fd = fd;

	ev.events = events;
	ev.data.ptr = tev;
	err = epoll_ctl(ep_fd, EPOLL_CTL_ADD, fd, &ev);
	if (err) {
		eprintf("Cannot add fd, %m\n");
		free(tev);
	} else
		list_add(&tev->e_list, &tgt_events_list);

	return err;
}

static struct tgt_event *tgt_event_lookup(int fd)
{
	struct tgt_event *tev;

	list_for_each_entry(tev, &tgt_events_list, e_list) {
		if (tev->fd == fd)
			return tev;
	}
	return NULL;
}

void tgt_event_del(int fd)
{
	struct tgt_event *tev;

	tev = tgt_event_lookup(fd);
	if (!tev) {
		eprintf("Cannot find event %d\n", fd);
		return;
	}

	epoll_ctl(ep_fd, EPOLL_CTL_DEL, fd, NULL);
	list_del(&tev->e_list);
	free(tev);
}

int tgt_event_modify(int fd, int events)
{
	struct epoll_event ev;
	struct tgt_event *tev;

	tev = tgt_event_lookup(fd);
	if (!tev) {
		eprintf("Cannot find event %d\n", fd);
		return -EINVAL;
	}

	ev.events = events;
	ev.data.ptr = tev;

	return epoll_ctl(ep_fd, EPOLL_CTL_MOD, fd, &ev);
}

#define IOCB_CMD_EPOLL_WAIT 9

static void io_prep_epoll_wait(struct iocb *iocb, int epfd,
			       struct epoll_event *events, int maxevents,
			       int timeout)
{
	memset(iocb, 0, sizeof(*iocb));
	iocb->aio_fildes = epfd;
	iocb->aio_lio_opcode = IOCB_CMD_EPOLL_WAIT;
	iocb->aio_reqprio = 0;

	iocb->u.c.nbytes = maxevents;
	iocb->u.c.offset = timeout;
	iocb->u.c.buf = events;
}

static void event_loop(void)
{
	int nevent, i, err;
	struct epoll_event events[1024];
	struct tgt_event *tev;
	struct iocb iocbs[1], *iocb;
	struct io_event aioevents[2048];
	struct timespec timeout = {1, 0};

	err = io_queue_init(2048, &ctx);
	if (err) {
		eprintf("%m\n");
		return;
	}

	iocb = iocbs;
	io_prep_epoll_wait(iocb, ep_fd, events, ARRAY_SIZE(events), -1);
	err = io_submit(ctx, 1, &iocb);

retry:
	nevent = io_getevents(ctx, 1, ARRAY_SIZE(aioevents), aioevents, &timeout);

	if (nevent < 0) {
		if (errno != EINTR) {
			eprintf("%m\n");
			exit(1);
		}
	} else if (nevent) {
		for (i = 0; i < nevent; i++) {
			if (iocb == aioevents[i].obj) {
				int j;
				for (j = 0; j < aioevents[i].res; j++) {
					tev = (struct tgt_event *) events[j].data.ptr;
					tev->handler(tev->fd, events[j].events, tev->data);
				}

				err = io_submit(ctx, 1, &iocb);
			} else {
				/* FIXME */
				target_cmd_io_done(aioevents[i].data, 0);
			}
		}
	} else
		schedule();

	if (!stop_daemon)
		goto retry;
}

static int lld_init(int *use_kernel)
{
	int i, err, nr;

	for (i = nr = 0; tgt_drivers[i]; i++) {
		if (tgt_drivers[i]->init) {
			err = tgt_drivers[i]->init();
			if (err)
				continue;
		}

		if (tgt_drivers[i]->use_kernel)
			(*use_kernel)++;
		nr++;
	}

	return nr;
}

int main(int argc, char **argv)
{
	struct sigaction sa_old;
	struct sigaction sa_new;
	int err, ch, longindex, nr_lld = 0, maxfds = MAX_FDS;
	int is_daemon = 1, is_debug = 0;
	int use_kernel = 0;

	/* do not allow ctrl-c for now... */
	sa_new.sa_handler = signal_catch;
	sigemptyset(&sa_new.sa_mask);
	sa_new.sa_flags = 0;
	sigaction(SIGINT, &sa_new, &sa_old );
	sigaction(SIGPIPE, &sa_new, &sa_old );
	sigaction(SIGTERM, &sa_new, &sa_old );

	while ((ch = getopt_long(argc, argv, short_options, long_options,
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

	ep_fd = epoll_create(maxfds);
	if (ep_fd < 0) {
		fprintf(stderr, "can't create epoll fd, %m\n");
		exit(1);
	}

	nr_lld = lld_init(&use_kernel);
	if (!nr_lld) {
		fprintf(stderr, "No available low level driver!\n");
		exit(1);
	}

	if (is_daemon && daemon(0,0))
		exit(1);

	oom_adjust();

	err = log_init(program_name, LOG_SPACE_SIZE, is_daemon, is_debug);
	if (err)
		exit(1);

	if (use_kernel) {
		err = kreq_init();
		if (err) {
			eprintf("No kernel interface\n");
			exit(1);
		}
	}

	err = ipc_init();
	if (err)
		exit(1);

	event_loop();

	return 0;
}
