/*
 * Copyright(c) 2007 Intel Corporation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <linux/if.h>

#include "list.h"
#include "log.h"
#include "util.h"

#include "sa_event.h"

/*
 * Semi-opaque event structure.
 */
struct sa_event {
	struct list_head se_list;
	sa_event_handler_t *se_handler;
	void *se_arg;
};

/*
 * Event list head.
 */
struct sa_event_list {
	struct list_head se_head;
	int se_refcnt;	/* references to list header */
	unsigned int se_pending_events;	/* flags for pending events */
};

static void sa_event_list_release(struct sa_event_list *lp)
{
	if (!(--lp->se_refcnt))
		free(lp);
}

struct sa_event_list *sa_event_list_alloc(void)
{
	struct sa_event_list *lp;

	lp = zalloc(sizeof(*lp));
	if (lp) {
		INIT_LIST_HEAD(&lp->se_head);
		lp->se_refcnt = 1;
	}
	return lp;
}

void sa_event_list_free(struct sa_event_list *lp)
{
	struct sa_event *ev;
	struct sa_event *next;

	list_for_each_entry_safe(ev, next, &lp->se_head, se_list) {
		list_del(&ev->se_list);
		free(ev);
	}
	sa_event_list_release(lp);
}

/*
 * Queue handler for event.
 * The handler pointer is returned.  If the allocation fails, NULL is returned.
 * If the handler is already queued, just return the old handler pointer.
 */
struct sa_event *sa_event_enq(struct sa_event_list *lp,
			      void (*handler) (int, void *), void *arg)
{
	struct sa_event *ev;

	list_for_each_entry(ev, &lp->se_head, se_list) {
		if (ev->se_handler == handler && ev->se_arg == arg)
			return ev;
	}

	ev = zalloc(sizeof(*ev));
	if (ev) {
		ev->se_handler = handler;
		ev->se_arg = arg;
		list_add_tail(&ev->se_list, &lp->se_head);
	}
	return ev;
}

void sa_event_deq_ev(struct sa_event_list *lp, struct sa_event *ev)
{
	list_del(&ev->se_list);
	free(ev);
}

void
sa_event_deq(struct sa_event_list *lp, void (*handler) (int, void *), void *arg)
{
	struct sa_event *ev;
	struct sa_event *next;

	list_for_each_entry_safe(ev, next, &lp->se_head, se_list) {
		if (ev->se_handler == handler && ev->se_arg == arg) {
			list_del(&ev->se_list);
			free(ev);
			break;
		}
	}
}

/*
 * Call event on the list.
 * A temporary entry is inserted into the list to track our progress, and
 * we hold a reference on the list to make sure the whole thing isn't
 * removed.
 */
void sa_event_call(struct sa_event_list *lp, int rc)
{
	struct sa_event *ev;

	lp->se_refcnt++;

	list_for_each_entry(ev, &lp->se_head, se_list) {
		(*ev->se_handler) (rc, ev->se_arg);
	}

	sa_event_list_release(lp);
}

/*
 * Set an event to be delivered later.
 */
void sa_event_call_defer(struct sa_event_list *lp, int event)
{
	lp->se_pending_events |= 1U << event;
}

/*
 * Cancel an event that might've been deferred.
 */
void sa_event_call_cancel(struct sa_event_list *lp, int event)
{
	lp->se_pending_events &= ~(1U << event);
}

/*
 * Deliver deferred events.
 */
void sa_event_send_deferred(struct sa_event_list *lp)
{
	u_int32_t mask;
	u_int event;

	while ((mask = lp->se_pending_events)) {
		event = ffs(mask) - 1;
		sa_event_call_cancel(lp, event);
		sa_event_call(lp, event);
	}
}
