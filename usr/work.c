/*
 * bogus scheduler
 *
 * Copyright (C) 2006-2007 FUJITA Tomonori <tomof@acm.org>
 * Copyright (C) 2006-2007 Mike Christie <michaelc@cs.wisc.edu>
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

#include "list.h"
#include "util.h"
#include "log.h"
#include "work.h"

static unsigned int jiffies;
static LIST_HEAD(active_work_list);
static LIST_HEAD(inactive_work_list);

void add_work(struct tgt_work *work, unsigned int second)
{
	unsigned int when;
	struct tgt_work *ent;

	if (second) {
		when = second / TGTD_TICK_PERIOD;
		if (!when)
			when = 1;

		work->when = when + jiffies;

		list_for_each_entry(ent, &inactive_work_list, entry) {
			if (before(work->when, ent->when))
				break;
		}

		list_add_tail(&work->entry, &ent->entry);
	} else
		list_add_tail(&work->entry, &active_work_list);
}

void del_work(struct tgt_work *work)
{
	list_del_init(&work->entry);
}

/*
 * this function is called only when the system is idle. So this
 * scheduler is pretty bogus. Your job would be delayed unexpectedly.
 */
void schedule(void)
{
	struct tgt_work *work, *n;

	list_for_each_entry_safe(work, n, &inactive_work_list, entry) {
		if (after(jiffies, work->when)) {
			list_del(&work->entry);
			list_add_tail(&work->entry, &active_work_list);
		} else
			break;
	}

	while (!list_empty(&active_work_list)) {
		work = list_first_entry(&active_work_list,
					struct tgt_work, entry);
		list_del_init(&work->entry);
		work->func(work->data);
	}

	jiffies++;
}
