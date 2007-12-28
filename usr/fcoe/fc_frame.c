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
#include <sys/epoll.h>
#include <linux/if.h>

#include "list.h"
#include "log.h"
#include "util.h"

#include "net_types.h"
#include "fc_fs.h"
#include "fc_types.h"
#include "fc_frame.h"
#include "crc32_le.h"

#define FC_FRAME_ACTIVE 0xd00d1234UL	/* clean pattern to catch double free */
#define FC_FRAME_FREE   0xdeadbeefUL	/* dirty pattern to catch double free */

/*
 * Check the CRC in a frame.
 */
u_int32_t fc_frame_crc_check(struct fc_frame *fp)
{
	u_int32_t crc;
	u_int32_t error;
	const u_int8_t *bp;
	u_int len;

	fp->fr_flags &= ~FCPHF_CRC_UNCHECKED;
	len = (fp->fr_len + 3) & ~3;	/* round up length to include fill */
	bp = (const u_int8_t *)fp->fr_hdr;
	crc = ~crc32_sb8_64_bit(~0, bp, len);
	error = crc ^ *(u_int32_t *) (bp + len);
	return (error);
}

struct fc_frame *fc_frame_alloc_fill(struct fc_port *port, size_t payload_len)
{
	struct fc_frame *fp;
	size_t fill;

	fill = payload_len % 4;
	if (fill != 0)
		fill = 4 - fill;
	fp = fc_port_frame_alloc(port, payload_len + fill);
	if (fp) {
		fp->fr_len -= fill;
		memset((char *)fp->fr_hdr + fp->fr_len, 0, fill);
	}
	return fp;
}

/*
 * Allocate frame header and buffer.
 * These are currently allocated in a single allocation.
 * The length argument does not include room for the fc_frame_header.
 */

struct fc_frame *fc_frame_alloc_int(size_t len)
{
	struct fc_frame *fp;

	len += sizeof(struct fc_frame_header);
	fp = malloc(len + sizeof(*fp));
	if (fp) {
		memset(fp, 0, sizeof(fp));
		fp->fr_hdr = (struct fc_frame_header *)(fp + 1);
		fp->fr_len = (u_int16_t) len;
		fp->fr_free = (void (*)(struct fc_frame *))free;
	}
	return fp;
}

/*
 * Callback for freeing a frame allocated staticly.
 * This only marks the frame for debugging and makes it unusable.
 */
void fc_frame_free_static(struct fc_frame *fp)
{
	fp->fr_flags |= FCPHF_FREED;
	fp->fr_hdr = NULL;
	fp->fr_len = 0;
}
