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
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <malloc.h>

#include "crc32_le.h"

extern uint32_t crc_tableil8_o32[256];
extern uint32_t crc_tableil8_o40[256];
extern uint32_t crc_tableil8_o48[256];
extern uint32_t crc_tableil8_o56[256];
extern uint32_t crc_tableil8_o64[256];
extern uint32_t crc_tableil8_o72[256];
extern uint32_t crc_tableil8_o80[256];
extern uint32_t crc_tableil8_o88[256];

typedef union {
	uint32_t w;
	uint8_t b[4];
} crc_t;

typedef union {
	uint64_t ll;
	uint32_t w[2];
	uint8_t b[8];
} data_t;

uint32_t
crc32_sb8_64_bit(uint32_t crc_in, const uint8_t *p_buf, uint32_t length)
{
	crc_t crc;
	uint32_t *p0, *p1, *p2, *p3;

	crc.w = crc_in;
	for (; length && ((ptrdiff_t) p_buf & 7); length--)
		crc.w = crc_tableil8_o32[crc.b[0] ^ *p_buf++] ^ (crc.w >> 8);
	for (; length >= 8; length -= 8) {
		data_t data;

		data.ll = *(uint64_t *) p_buf;
		p_buf += 8;
		p0 = &crc_tableil8_o56[data.b[4]];
		p1 = &crc_tableil8_o48[data.b[5]];
		p2 = &crc_tableil8_o40[data.b[6]];
		p3 = &crc_tableil8_o32[data.b[7]];

		crc.w ^= data.w[0];
		crc.w = crc_tableil8_o88[crc.b[0]] ^
		    crc_tableil8_o80[crc.b[1]] ^
		    crc_tableil8_o72[crc.b[2]] ^
		    crc_tableil8_o64[crc.b[3]] ^
		    *p0 ^ *p1 ^ *p2 ^ *p3;
	}
	while (length--)
		crc.w = crc_tableil8_o32[crc.b[0] ^ *p_buf++] ^ (crc.w >> 8);
	return crc.w;
}

uint32_t
crc32_copy(uint32_t crc_in, uint8_t *dest, const uint8_t * p_buf,
	   uint32_t length)
{
	crc_t crc;
	uint32_t *p0, *p1, *p2, *p3;

	crc.w = crc_in;
	for (; length && ((ptrdiff_t) p_buf & 7); length--) {
		*dest++ = *p_buf;
		crc.w = crc_tableil8_o32[crc.b[0] ^ *p_buf++] ^ (crc.w >> 8);
	}
	for (; length >= 8; length -= 8) {
		data_t	data;

		data.ll = *(uint64_t *) p_buf;
		* (uint64_t *) dest = data.ll;
		dest += 8;
		p_buf += 8;
		p0 = &crc_tableil8_o56[data.b[4]];
		p1 = &crc_tableil8_o48[data.b[5]];
		p2 = &crc_tableil8_o40[data.b[6]];
		p3 = &crc_tableil8_o32[data.b[7]];

		crc.w ^= data.w[0];
		crc.w = crc_tableil8_o88[crc.b[0]] ^
		    crc_tableil8_o80[crc.b[1]] ^
		    crc_tableil8_o72[crc.b[2]] ^
		    crc_tableil8_o64[crc.b[3]] ^
		    *p0 ^ *p1 ^ *p2 ^ *p3;
	}
	while (length--) {
		*dest++ = *p_buf;
		crc.w = crc_tableil8_o32[crc.b[0] ^ *p_buf++] ^ (crc.w >> 8);
	}
	return crc.w;
}
