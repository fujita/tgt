/*++
 *
 * Copyright (c) 2004-2006 Intel Corporation - All Rights Reserved
 *
 * This software program is licensed subject to the BSD License,
 * available at http://www.opensource.org/licenses/bsd-license.html
 *
 --*/

#ifndef __LIBTPS_CRC32C_LE_H_
#define __LIBTPS_CRC32C_LE_H_

/**
 *
 * Routine Description:
 *
 * Computes the CRC32c checksum for the specified buffer using the slicing by 8
 * algorithm over 64 bit quantities.
 *
 * Arguments:
 *
 *      p_running_crc - pointer to the initial or final remainder value
 *                      used in CRC computations. It should be set to
 *                      non-NULL if the mode argument is equal to CONT or END
 *      p_buf - the packet buffer where crc computations are being performed
 *      length - the length of p_buf in bytes
 *      init_bytes - the number of initial bytes that need to be procesed before
 *                   aligning p_buf to multiples of 4 bytes
 *      mode - can be any of the following: BEGIN, CONT, END, BODY, ALIGN
 *
 * Return value:
 *
 *      The computed CRC32c value
 */
u_int32_t crc32_sb8_64_bit(u_int32_t p_running_crc, const u_int8_t *p_buf,
			   u_int32_t length);

/*
 * Like crc32_sb8_64_bit, but also copy the buffer while doing the CRC.
 */
u_int32_t crc32_copy(u_int32_t p_running_crc, u_int8_t *dest,
		     const u_int8_t *p_buf, u_int32_t length);

#endif /* __LIBTPS_CRC32C_LE_H_ */
