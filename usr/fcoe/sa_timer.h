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

#ifndef _LIBSA_TIMER_H_
#define _LIBSA_TIMER_H_

#include "work.h"

/*
 * Timer facility.
 */

struct sa_timer {
	struct tgt_work tm_list;
};


#define SA_TIMER_UNITS  (1000 * 1000UL)	/* number of timer ticks per second */

/*
 * Initialize a timer structure.  Set handler.
 */
static inline void sa_timer_init(struct sa_timer *tm,
					void (*handler)(void *), void *arg)
{
	INIT_LIST_HEAD(&tm->tm_list.entry);
	tm->tm_list.func = handler;
	tm->tm_list.data = arg;
}

/*
 * Test whether the timer is active.
 */
static inline int sa_timer_active(struct sa_timer *tm)
{
	return !list_empty(&tm->tm_list.entry);
}

/*
 * Set timer to fire.   Delta is in microseconds from now.
 */
void sa_timer_set(struct sa_timer *, u_long delta);

/*
 * Cancel timer.
 */
void sa_timer_cancel(struct sa_timer *);

#endif /* _LIBSA_TIMER_H_ */
