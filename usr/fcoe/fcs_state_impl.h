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

#ifndef _OPENFC_FCS_STATE_IMPL_H_
#define _OPENFC_FCS_STATE_IMPL_H_

#include "sa_timer.h"

/*
 * Private state structure.
 */
struct fcs_state {
	struct fcs_create_args	fs_args;
	struct fc_virt_fab *fs_vf;		/* virtual fabric (domain) */
	struct fc_local_port *fs_local_port;	/* local port */
	struct fc_port	*fs_inner_port;		/* port used by local port */
	uint8_t		fs_disc_done;		/* discovery complete */
};

void fcs_ev_destroy(void);

struct fc_els_rscn_page;

void fcs_ev_add(struct fcs_state *, u_int, void *, size_t);
void fcs_ev_els(void *, u_int, void *, size_t);

#endif /* _OPENFC_FCS_STATE_IMPL_H_ */
