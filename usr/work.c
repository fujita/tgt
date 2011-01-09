/*
 * work scheduler, loosely timer-based
 *
 * Copyright (C) 2006-2007 FUJITA Tomonori <tomof@acm.org>
 * Copyright (C) 2006-2007 Mike Christie <michaelc@cs.wisc.edu>
 * Copyright (C) 2011 Alexander Nezhinsky <alexandern@voltaire.com>
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
#include <stdlib.h>
#include <stdint.h>
#include <signal.h>
#include <sys/epoll.h>

#include "list.h"
#include "util.h"
#include "log.h"
#include "work.h"
#include "tgtd.h"

#define time_before(w1, w2)     timercmp(w1, w2, <)

#define WORK_TIMER_INT_SEC      0
#define WORK_TIMER_INT_MSEC     250
#define WORK_TIMER_INT_USEC     (WORK_TIMER_INT_MSEC * 1000)

static struct itimerval work_timer = {
	{WORK_TIMER_INT_SEC, WORK_TIMER_INT_USEC},
	{WORK_TIMER_INT_SEC, WORK_TIMER_INT_USEC}
};

static int timer_started;
static int timer_pending;
static int timer_fd[2] = {0, 0};

static LIST_HEAD(active_work_list);
static LIST_HEAD(inactive_work_list);

static void execute_work(void);

static inline void work_timer_schedule_evt(void)
{
	unsigned int n = 0;
	int err;

	if (timer_pending)
		return;

	timer_pending = 1;

	err = write(timer_fd[1], &n, sizeof(n));
	if (err < 0)
		eprintf("Failed to write to pipe, %m\n");
}

static void work_timer_sig_handler(int data)
{
	work_timer_schedule_evt();
}

static void work_timer_evt_handler(int fd, int events, void *data)
{
	unsigned int n;
	int err;

	err = read(timer_fd[0], &n, sizeof(n));
	if (err < 0) {
		eprintf("Failed to read from pipe, %m\n");
		return;
	}

	timer_pending = 0;

	execute_work();
}

int work_timer_start(void)
{
	struct sigaction s;
	int err;

	if (timer_started)
		return 0;

	timer_started = 1;

	sigemptyset(&s.sa_mask);
	sigaddset(&s.sa_mask, SIGALRM);
	s.sa_flags = 0;
	s.sa_handler = work_timer_sig_handler;
	err = sigaction(SIGALRM, &s, NULL);
	if (err) {
		eprintf("Failed to setup timer handler\n");
		goto timer_err;
	}

	err = setitimer(ITIMER_REAL, &work_timer, 0);
	if (err) {
		eprintf("Failed to set timer\n");
		goto timer_err;
	}

	err = pipe(timer_fd);
	if (err) {
		eprintf("Failed to open timer pipe\n");
		goto timer_err;
	}

	err = tgt_event_add(timer_fd[0], EPOLLIN,
			    work_timer_evt_handler, NULL);
	if (err) {
		eprintf("failed to add timer event, fd:%d\n", timer_fd[0]);
		goto timer_err;
	}

	dprintf("started, timeout: %d sec %d msec\n",
		WORK_TIMER_INT_SEC, WORK_TIMER_INT_MSEC);
	return 0;

timer_err:
	work_timer_stop();
	return err;
}

int work_timer_stop(void)
{
	int err;

	if (!timer_started)
		return 0;

	timer_started = 0;

	tgt_event_del(timer_fd[0]);

	if (timer_fd[0] > 0)
		close(timer_fd[0]);
	if (timer_fd[1] > 0)
		close(timer_fd[1]);

	err = setitimer(ITIMER_REAL, 0, 0);
	if (err)
		eprintf("Failed to stop timer\n");
	else
		dprintf("Timer stopped\n");

	return err;
}

void add_work(struct tgt_work *work, unsigned int second)
{
	struct tgt_work *ent;
	int err;

	if (second) {
		err = gettimeofday(&work->when, NULL);
		if (err) {
			eprintf("gettimeofday failed, %m\n");
			return;
		}
		work->when.tv_sec += second;

		list_for_each_entry(ent, &inactive_work_list, entry) {
			if (time_before(&work->when, &ent->when))
				break;
		}

		list_add_tail(&work->entry, &ent->entry);
	} else {
		list_add_tail(&work->entry, &active_work_list);
		work_timer_schedule_evt();
	}
}

void del_work(struct tgt_work *work)
{
	list_del_init(&work->entry);
}

static void execute_work()
{
	struct timeval cur_time;
	struct tgt_work *work, *n;
	int err;

	err = gettimeofday(&cur_time, NULL);
	if (err) {
		eprintf("gettimeofday failed, %m\n");
		return;
	}

	list_for_each_entry_safe(work, n, &inactive_work_list, entry) {
		if (time_before(&cur_time, &work->when))
			break;

		list_del(&work->entry);
		list_add_tail(&work->entry, &active_work_list);
	}

	while (!list_empty(&active_work_list)) {
		work = list_first_entry(&active_work_list,
					struct tgt_work, entry);
		list_del_init(&work->entry);
		work->func(work->data);
	}
}

