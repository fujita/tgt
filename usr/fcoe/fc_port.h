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

#ifndef _LIBFC_PORT_H_
#define _LIBFC_PORT_H_

/*
 * Fibre Channel virtual switch ports.
 */
#include "sa_event.h"
#include "fc_event.h"

struct fc_frame;

/*
 * Port control functions.
 */
enum fc_port_ctl {
	FC_PCTL_NONE = 0,	/* unused */
	FC_PCTL_GET_WWNN,	/* get node world wide name */
	FC_PCTL_GET_WWPN,	/* get port world wide name */
	FC_PCTL_GET_BBC,	/* get buffer-to-buffer credits */
	FC_PCTL_SET_BBC,	/* set buffer-to-buffer credits */
};

/*
 * Port - egress and event handlers for packets using specific connection.
 *   Handle used by frames, sequences, and exchanges indicating where
 *   the sequence was received and where replies should be sent.
 */
struct fc_port {
	/*
	 * Handler for packets received by this port from the transport below.
	 */
	void		(*np_ingress)(void *arg, struct fc_frame *);
	void		*np_ingress_arg;	/* ingress argument */

	/*
	 * Handler for packets to be sent out of this port, e.g. from switch
	 * or HBA driver.
	 */
	int		(*np_egress)(void *arg, struct fc_frame *);
	void		*np_egress_arg;	/* egress argument */
	int		(*np_egress_ctl)(void *arg, enum fc_port_ctl,
					void *, size_t);

	struct sa_event_list *np_events;
	u_int32_t	np_max_frame;	/* max sending frame size for port */
	int		np_ready;	/* port is usable */

	struct fc_frame *(*np_frame_alloc)(size_t payload_len);
};

/*
 * methods.
 */
struct fc_port *fc_port_alloc(void);

void fc_port_free(struct fc_port *);

/*
 * Set or get the max frame size for port.
 */
void fc_port_set_max_frame_size(struct fc_port *, u_int);
u_int fc_port_get_max_frame_size(struct fc_port *);

/*
 * Send a frame out of the switch or end-point from the given port.
 * Returns non-zero if frame cannot be sent.
 * Always consumes the frame, regardless of error.
 */
int fc_port_egress(struct fc_port *, struct fc_frame *);

/*
 * Set egress handler - handles frames arriving at the port from inside switch.
 */
void fc_port_set_egress(struct fc_port *,
			int (*egress_func) (void *arg, struct fc_frame *),
			void *arg);

/*
 * Set ingress handler - handles frames arriving at the port from the wire.
 */
void fc_port_set_ingress(struct fc_port *,
			 void (*ingress_func) (void *arg, struct fc_frame *),
			 void *arg);

/*
 * Set event handler.
 */
struct sa_event *fc_port_enq_handler(struct fc_port *,
					sa_event_handler_t *, void *arg);

/*
 * Unset event handler.
 */
void fc_port_deq_handler(struct fc_port *, sa_event_handler_t *, void *arg);

/*
 * Send event to a port's event handlers.
 */
void fc_port_send_event(struct fc_port *, enum fc_event);

/*
 * Send a Fibre Channel frame into a port.
 */
void fc_port_ingress(struct fc_port *, struct fc_frame *);

/*
 * Close port from ingress or egress side.
 */
void fc_port_close_ingress(struct fc_port *);
void fc_port_close_egress(struct fc_port *);

/*
 * Get ingress or egress argument.
 */
void *fc_port_get_ingress_arg(struct fc_port *);
void *fc_port_get_egress_arg(struct fc_port *);

/*
 * Return non-zero if port is usable for I/O.
 */
int fc_port_ready(struct fc_port *);

/*
 * Issue port control function.
 * Returns the number of bytes copied to buffer, or a negative error number.
 */
int fc_port_egress_control(struct fc_port *,
			   enum fc_port_ctl, void *buf, size_t len);

/*
 * Setup port control handler.
 */
void fc_port_set_egress_control(struct fc_port *,
				int (*)(void *arg, enum fc_port_ctl,
					void *, size_t));

/*
 * Set frame allocation function for port.
 */
static inline void fc_port_set_frame_alloc(struct fc_port *port,
	struct fc_frame *(*fcn)(size_t))
{
	port->np_frame_alloc = fcn;
}

#endif /* _LIBFC_PORT_H_ */
