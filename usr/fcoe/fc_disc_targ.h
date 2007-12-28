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

#ifndef _LIBFC_DISC_TARG_H_
#define _LIBFC_DISC_TARG_H_

/*
 * Fibre Channel Target discovery.
 *
 * Returns non-zero if discovery cannot be started.
 *
 * Callback is called for each target remote port found in discovery.
 * When discovery is complete, the callback is called with a NULL remote port.
 */
int fc_disc_targ_start(struct fc_local_port *, u_int fc4_type,
			void (*callback)(void *arg,
				struct fc_remote_port *, enum fc_event),
			void *arg);

/*
 * Registers a callback with discovery
 */
int fc_disc_targ_register_callback(struct fc_local_port *, u_int fc4_type,
			void (*callback)(void *arg,
				struct fc_remote_port *, enum fc_event),
			void *arg);

int fc_disc_targ_restart(struct fc_local_port *);

void fc_disc_targ_single(struct fc_local_port *, fc_fid_t);

#endif /* _LIBFC_DISC_TARG_H_ */
