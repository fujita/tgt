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

#ifndef _LIBFC_EVENT_H_
#define _LIBFC_EVENT_H_

/*
 * Definitions for events that can occur on local ports, remote ports, and
 * sessions, and may be handled by state machines for these objects.
 * The order and number of these may effect state machine table sizes.
 */
enum fc_event {
	FC_EV_NONE = 0,		/* non-event */
	FC_EV_ACC,		/* request accepted */
	FC_EV_RJT,		/* request rejected */
	FC_EV_TIMEOUT,		/* timer expired */
	FC_EV_START,		/* upper layer requests startup / login */
	FC_EV_STOP,		/* upper layer requests shutdown / logout */
	FC_EV_READY,		/* lower level is ready */
	FC_EV_DOWN,	        /* lower level has no link or connection */
	FC_EV_CLOSED,		/* lower level shut down or disabled */
	FC_EV_LIMIT		/* basis for private events */
};

#endif /* _LIBFC_EVENT_H_ */
