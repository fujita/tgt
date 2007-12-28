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

#ifndef _LIBFC_VIRT_FAB_H_
#define _LIBFC_VIRT_FAB_H_

#include "fc_encaps.h"

/*
 * Fibre Channel Virtual Fabric.
 * This facility coordinates remote ports and local ports to the same
 * virtual fabric.
 *
 * Struct fc_virt_fab is semi-opaque structure.
 */
struct fc_virt_fab;
struct fc_virt_fab *fc_virt_fab_alloc(u_int tag, enum fc_class,
				      fc_xid_t min_xid, fc_xid_t max_fid);
void fc_virt_fab_free(struct fc_virt_fab *);

/*
 * Default exchange ID limits for user applications.
 */
#define	FC_VF_MIN_XID	0x101
#define	FC_VF_MAX_XID	0x2ff

#endif /* _LIBFC_VIRT_FAB_H_ */
