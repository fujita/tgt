/*
 * bogus scheduler
 *
 * Copyright (C) 2006-2007 FUJITA Tomonori <tomof@acm.org>
 * Copyright (C) 2006-2007 Mike Christie <michaelc@cs.wisc.edu>
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

#include <stdlib.h>
#include <stdint.h>

#include "list.h"
#include "util.h"
#include "log.h"
#include "work.h"

int stop_daemon;

static unsigned int jiffies;
static LIST_HEAD(active_work_list);
static LIST_HEAD(inactive_work_list);

void enqueue_work(struct tgt_work *work, unsigned int second)
{
	unsigned int when;
	struct tgt_work *ent;

	when = second * SCHED_HZ;

	if (when) {

		list_for_each_entry(ent, &inactive_work_list, entry) {
			if (before(when, ent->when))
				break;
		}

		list_add_tail(&work->entry, &ent->entry);
	} else
		list_add_tail(&work->entry, &active_work_list);
}

void dequeue_work(struct tgt_work *work)
{
	list_del(&work->entry);
}

/*
 * this function is called only when the system is idle. So this
 * scheduler is pretty bogus. Your job would be delayed unexpectedly.
 */
void schedule(void)
{
	struct tgt_work *work;

	jiffies++;

	list_for_each_entry(work, &inactive_work_list, entry) {
		if (after(work->when, jiffies)) {
			list_del(&work->entry);
			enqueue_work(work, 0);
		} else
			break;
	}

	while (!list_empty(&active_work_list)) {
		work = list_entry(active_work_list.next, struct tgt_work, entry);
		work->func(work->data);
	}
}
