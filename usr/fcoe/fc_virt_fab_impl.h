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

#ifndef _LIBFC_FC_VIRT_FAB_IMPL_H_
#define _LIBFC_FC_VIRT_FAB_IMPL_H_

struct fc_virt_fab {
	uint		vf_tag;		/* virtual fabric tag (or zero) */
	struct list_head vf_remote_ports;	/* remote ports */
	struct sa_hash	*vf_rport_by_fid;	/* remote ports by FCID */
	struct sa_hash	*vf_rport_by_wwpn;	/* remote ports by WWPN */
	struct sa_hash	*vf_lport_by_fid;	/* local ports by FCID */
	struct sa_hash	*vf_sess_by_fids;	/* sessions by FCID pairs */
	struct list_head vf_local_ports;	/* list of local ports */
	struct fc_exch_mgr *vf_exch_mgr;	/* exchange mgr for fabric */
};

/*
 * Locking code.
 */
static inline void fc_virt_fab_lock(struct fc_virt_fab *vp)
{
}

static inline void fc_virt_fab_unlock(struct fc_virt_fab *vp)
{
}

#endif /* _LIBFC_FC_VIRT_FAB_IMPL_H_ */
