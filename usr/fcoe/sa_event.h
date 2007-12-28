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

#ifndef _LIBSA_SA_EVENT_H_
#define _LIBSA_SA_EVENT_H_

/*
 * General event mechanism.
 *
 * Events are separately locked and MP-safe in the kernel.
 *
 * Events are scheduled on a list headed by struct sa_event_head.
 *
 * sa_event_list_init(&head) initializes the list.
 * sa_event_list_destroy(&head) frees any resources associated with the list.
 *
 * sa_event_enq(&head, cb, arg) allocates and enqueues an event handler.
 * The arguments specify the callback and argument for the callback.
 *
 * sa_event_deq(&head, cb, arg) dequeues a previously scheduled event specified
 * by handler and argument, which must be unique.
 *
 * sa_event_deq_ev(&head, ev) dequeues a previously scheduled event by pointer.
 *
 * sa_event_call(&head, rc), calls all of the event handlers on the list.
 *
 * sa_event_call does not dequeue the event.  The list may change during the
 * callback.
 */

/*
 * Semi-opaque event list element.
 */
struct sa_event;		/* event list element */
struct sa_event_list;		/* list header */

/*
 * Callback type for event handlers.
 */
typedef void (sa_event_handler_t) (int rc, void *arg);

/*
 * Functions.
 */
struct sa_event_list *sa_event_list_alloc(void);
void sa_event_list_free(struct sa_event_list *);
struct sa_event *sa_event_enq(struct sa_event_list *, sa_event_handler_t *,
			      void *arg);
void sa_event_deq(struct sa_event_list *, sa_event_handler_t *, void *);
void sa_event_deq_ev(struct sa_event_list *, struct sa_event *);

void sa_event_call(struct sa_event_list *, int rc);

/*
 * Functions managing deferred events.
 */
void sa_event_call_defer(struct sa_event_list *, int event);
void sa_event_call_cancel(struct sa_event_list *, int event);
void sa_event_send_deferred(struct sa_event_list *);

#endif /* _LIBSA_SA_EVENT_H_ */
