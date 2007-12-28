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

#include "sa_timer.h"

/*
 * Set timer to fire.   Delta is in microseconds from now.
 */
void sa_timer_set(struct sa_timer *tm, u_long delta_usec)
{
	add_work(&tm->tm_list, delta_usec / SA_TIMER_UNITS);
}

/*
 * Cancel timer if it is active.
 */
void sa_timer_cancel(struct sa_timer *tm)
{
	if (sa_timer_active(tm))
		del_work(&tm->tm_list);
}
