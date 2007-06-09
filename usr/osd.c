/*
 * SCSI object storage device command processing
 *
 * Copyright (C) 2006-2007 Pete Wyckoff <pw@osc.edu>
 * Copyright (C) 2007 FUJITA Tomonori <tomof@acm.org>
 * Copyright (C) 2007 Mike Christie <michaelc@cs.wisc.edu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "list.h"
#include "util.h"
#include "tgtd.h"
#include "target.h"
#include "driver.h"
#include "scsi.h"
#include "spc.h"

static int osd_varlen_cdb(int host_no, struct scsi_cmd *cmd)
{
	unsigned char key = ILLEGAL_REQUEST, asc = 0x25;

	dprintf("cdb[0] %x datalen %u\n", cmd->scb[0], cmd->len);
	if (cmd->scb[7] != 200 - 8) {
		eprintf("request size %d wrong, should be 200\n",
			cmd->scb[7] + 8);
		sense_data_build(cmd, key, asc, 0);
		cmd->len = 0;
		return SAM_STAT_CHECK_CONDITION;
	}

/* 	return SAM_STAT_GOOD; */
	return cmd->c_target->bst->bs_cmd_submit(cmd);
}

static int osd_lu_init(struct scsi_lu *lu)
{
	if (spc_lu_init(lu))
		return -ENOMEM;

	memcpy(lu->attrs->product_id, "OSD", 16);
	lu->attrs->sense_format = 1;
	lu->attrs->version_desc[0] = 0x0340; /* OSD */
	lu->attrs->version_desc[1] = 0x0960; /* iSCSI */
	lu->attrs->version_desc[2] = 0x0300; /* SPC-3 */

	return 0;
}

static int osd_lu_exit(struct scsi_lu *lu)
{
	return 0;
}

struct device_type_template osd_template = {
	.type		= TYPE_OSD,
	.name		= "osd",
	.lu_init	= osd_lu_init,
	.lu_exit	= osd_lu_exit,
	.ops		= {
		[0x00 ... 0x0f] = {spc_illegal_op},

		/* 0x10 */
		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_inquiry,},
		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_illegal_op,},

		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_illegal_op,},

		[0x20 ... 0x6f] = {spc_illegal_op},

		/* 0x70 */
		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_illegal_op,},

		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_illegal_op,},
		{osd_varlen_cdb,},

		[0x80 ... 0x9f] = {spc_illegal_op},

		/* 0xA0 */
		{spc_report_luns,},
		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_illegal_op,},

		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_illegal_op,},

		[0xb0 ... 0xff] = {spc_illegal_op},
	}
};
