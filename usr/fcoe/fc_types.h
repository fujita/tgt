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

#ifndef _LIBFC_TYPES_H_
#define _LIBFC_TYPES_H_

#include "net_types.h"

/*
 * Host-order type definitions for Fibre Channel.
 */

/*
 * Note, in order for fc_wwn_t to be acceptable for %qx format strings,
 * it cannot be declared as uint64_t.
 */
typedef unsigned long long fc_wwn_t;	/* world-wide name */
typedef uint32_t	fc_fid_t;	/* fabric address */
typedef uint16_t	fc_xid_t;	/* exchange ID */

/*
 * Encapsulation / port option flags.
 */
#define	FC_OPT_DEBUG_RX     0x01	/* log debug messages */
#define	FC_OPT_DEBUG_TX     0x02	/* log debug messages */
#define	FC_OPT_DEBUG        (FC_OPT_DEBUG_RX | FC_OPT_DEBUG_TX)
#define	FC_OPT_NO_TX_CRC    0x04	/* don't generate sending CRC */
#define	FC_OPT_NO_RX_CRC    0x08	/* don't check received CRC */
#define	FC_OPT_FCIP_NO_SFS  0x10	/* No special frame (FCIP only) */
#define	FC_OPT_PASSIVE      0x20	/* Responding to connect */
#define	FC_OPT_SET_MAC      0x40	/* use non-standard MAC addr (FCOE) */
#define	FC_OPT_FCOE_OLD     0x80	/* use old prototype FCoE encaps */

/*
 * Convert 48-bit IEEE MAC address to 64-bit FC WWN.
 */
fc_wwn_t fc_wwn_from_mac(u_int64_t, u_int32_t scheme, u_int32_t port);
fc_wwn_t fc_wwn_from_wwn(fc_wwn_t, u_int32_t scheme, u_int32_t port);

#endif /* _LIBFC_TYPES_H_ */
