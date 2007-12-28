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

#ifndef _FC_FCOE_OLD_H_
#define	_FC_FCOE_OLD_H_

/*
 * FCoE - Fibre Channel over Ethernet - old version.
 */

/*
 * Start of frame values.
 * For FCOE the SOF value is encoded in 4 bits by simply trimming the
 * standard RFC 3643 encapsulation values.  See fc/encaps.h.
 *
 * The following macros work for class 3 and class F traffic.
 * It is still required to use net access functions to do the byte swapping.
 *
 * SOF code	Normal	 FCOE
 *  SOFf	0x28	    8
 *  SOFi3	0x2e	    e
 *  SOFn3	0x36	    6
 */
#define	FC_FCOE_ENCAPS_LEN_SOF(len, sof) \
		((FC_FCOE_VER << 14) | (((len) & 0x3ff) << 4) | ((sof) & 0xf))
#define	FC_FCOE_DECAPS_LEN(n)	(((n) >> 4) & 0x3ff)
#define	FC_FCOE_DECAPS_SOF(n) \
		(((n) & 0x8) ? (((n) & 0xf) + 0x20) : (((n) & 0xf) + 0x30))

/*
 * FCoE frame header
 * This follows the VLAN header, which includes the ethertype.
 * The version is the MS 2 bits, followed by the 10-bit length (in 32b words),
 * followed by the 4-bit encoded SOF as the LSBs.
 */
struct fcoe_hdr_old {
	net16_t		fcoe_plen;	/* fc frame len and SOF */
};

/*
 * FCoE CRC & EOF
 */
struct fcoe_crc_eof_old {
	u_int32_t	fcoe_crc32;	/* CRC for FC packet */
	net8_t		fcoe_eof;	/* EOF from RFC 3643 */
} __attribute__((packed));

#endif /* _FC_FCOE_OLD_H_ */
