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
 *
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
#include "fc_types.h"
#include "fc_port.h"
#include "fc_frame.h"
#include "fc_exch.h"
#include "fc_fs.h"
#include "fc_encaps.h"

/*
 * Null ingress handler.
 */
static void fc_port_null_ingress(void *arg, struct fc_frame *fp)
{
	fc_frame_free(fp);
}

/*
 * Null egress handler.
 */
static int fc_port_null_egress(void *arg, struct fc_frame *fp)
{
	fc_frame_free(fp);
	return 0;
}

/*
 * Create a new fibre-channel port.
 */
struct fc_port *fc_port_alloc(void)
{
	struct fc_port *port;

	port = zalloc(sizeof(*port));
	if (port) {
		port->np_ingress = fc_port_null_ingress;
		port->np_egress = fc_port_null_egress;
		port->np_max_frame =
		    FC_MAX_PAYLOAD + sizeof(struct fc_frame_header);
		port->np_ready = 1;
		port->np_events = sa_event_list_alloc();

		port->np_frame_alloc = fc_frame_alloc_int;
		if (!port->np_events) {
			free(port);
			port = NULL;
		}
	}
	return port;
}

/*
 * Free fibre-channel port.
 */
void fc_port_free(struct fc_port *port)
{

	sa_event_list_free(port->np_events);
	free(port);
}

/*
 * Set max frame size for port.
 */
void fc_port_set_max_frame_size(struct fc_port *port, u_int mfs)
{
	mfs &= ~3;
	if (mfs > FC_MAX_FRAME)
		mfs = FC_MAX_FRAME;
	port->np_max_frame = mfs;
}

/*
 * Get max frame size for port.
 */
u_int fc_port_get_max_frame_size(struct fc_port *port)
{
	return port->np_max_frame;
}

/*
 * Set egress handler for port.
 */
void
fc_port_set_egress(struct fc_port *port,
		   int (*egress) (void *arg, struct fc_frame *), void *arg)
{
	port->np_egress = egress;
	port->np_egress_arg = arg;
}

/*
 * Set ingress handler for port.
 */
void
fc_port_set_ingress(struct fc_port *port,
		    void (*ingress) (void *arg, struct fc_frame *), void *arg)
{
	port->np_ingress = ingress;
	port->np_ingress_arg = arg;
}

/*
 * Close egress side of port.
 */
void fc_port_close_egress(struct fc_port *port)
{
	port->np_egress = fc_port_null_egress;
	port->np_egress_arg = NULL;
	if (port->np_ingress == fc_port_null_ingress)
		fc_port_free(port);
	else
		sa_event_call(port->np_events, FC_EV_CLOSED);
}

/*
 * Close ingress side of port.
 */
void fc_port_close_ingress(struct fc_port *port)
{
	port->np_ingress = fc_port_null_ingress;
	port->np_ingress_arg = NULL;
	if (port->np_egress == fc_port_null_egress)
		fc_port_free(port);
	else
		sa_event_call(port->np_events, FC_EV_CLOSED);
}

/*
 * Send a frame out of the switch or end-point from the given port.
 * E.g., called by an internal fabric controller communicating on an ISL port.
 * Ends up using the port's egress handler.
 */
int fc_port_egress(struct fc_port *port, struct fc_frame *fp)
{
	return (*port->np_egress) (port->np_egress_arg, fp);
}

/*
 * Send a frame into a port.
 */
void fc_port_ingress(struct fc_port *port, struct fc_frame *fp)
{
	(*port->np_ingress) (port->np_ingress_arg, fp);
}

/*
 * Set event handler.
 */
struct sa_event *fc_port_enq_handler(struct fc_port *port,
				     sa_event_handler_t *handler, void *arg)
{
	return sa_event_enq(port->np_events, handler, arg);
}

/*
 * Set event handler.
 */
void
fc_port_deq_handler(struct fc_port *port, sa_event_handler_t *handler,
		    void *arg)
{
	sa_event_deq(port->np_events, handler, arg);
}

/*
 * Invoke event on port.
 */
void fc_port_send_event(struct fc_port *port, enum fc_event event)
{
	if (event == FC_EV_READY)
		port->np_ready = 1;
	else if (event == FC_EV_CLOSED || event == FC_EV_DOWN)
		port->np_ready = 0;
	sa_event_call(port->np_events, event);
}

void *fc_port_get_ingress_arg(struct fc_port *port)
{
	return port->np_ingress_arg;
}

void *fc_port_get_egress_arg(struct fc_port *port)
{
	return port->np_egress_arg;
}

int fc_port_ready(struct fc_port *port)
{
	return port->np_ready;
}

/*
 * Port control handler.
 */
int
fc_port_egress_control(struct fc_port *port, enum fc_port_ctl op,
		       void *buf, size_t len)
{
	int rc = -EINVAL;

	if (port->np_egress_ctl != NULL)
		rc = (*port->np_egress_ctl) (port->np_egress_arg, op, buf, len);
	return rc;
}

/*
 * Set port control handler.
 */
void
fc_port_set_egress_control(struct fc_port *port,
			   int (*handler) (void *, enum fc_port_ctl,
					   void *, size_t))
{
	port->np_egress_ctl = handler;
}
