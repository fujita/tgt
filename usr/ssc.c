/*
 * SCSI stream command processing
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <linux/fs.h>

#include "list.h"
#include "util.h"
#include "tgtd.h"
#include "tgtadm_error.h"
#include "target.h"
#include "driver.h"
#include "scsi.h"
#include "spc.h"
#include "tgtadm_error.h"

#define BLK_SHIFT	9


static int ssc_rw(int host_no, struct scsi_cmd *cmd)
{
	int ret;
	unsigned char key = ILLEGAL_REQUEST;
	uint16_t asc = ASC_LUN_NOT_SUPPORTED;

	ret = device_reserved(cmd);
	if (ret)
		return SAM_STAT_RESERVATION_CONFLICT;

	cmd->scsi_cmd_done = target_cmd_io_done;

/* 	cmd->offset = (((cmd->scb[2] << 16) | (cmd->scb[3] << 8) | */
/* 			(cmd->scb[4])) << BLK_SHIFT); */

	ret = cmd->dev->bst->bs_cmd_submit(cmd);
	if (ret) {
		key = HARDWARE_ERROR;
		asc = ASC_INTERNAL_TGT_FAILURE;
	} else {
		set_cmd_mmapio(cmd);
		return SAM_STAT_GOOD;
	}

	cmd->offset = 0;
	scsi_set_in_resid_by_actual(cmd, 0);
	scsi_set_out_resid_by_actual(cmd, 0);

	sense_data_build(cmd, key, asc);
	return SAM_STAT_CHECK_CONDITION;
}

static int ssc_read_block_limit(int host_no, struct scsi_cmd *cmd)
{
	uint8_t *data;
	uint8_t buf[256];
	uint16_t blk_len = 0x200;

	memset(buf, 0, sizeof(buf));
	data = buf;

	data[0] = 9;
	data[2] = blk_len >> 8;
	data[3] = blk_len & 0x0ff;
	data[5] = blk_len >> 8;
	data[6] = blk_len & 0x0ff;

	memcpy(scsi_get_in_buffer(cmd), data, 6);
	eprintf("In ssc_read_block_limit \n");
	return SAM_STAT_GOOD;
}

static int ssc_lu_init(struct scsi_lu *lu)
{
	uint64_t size;
	uint8_t *data;

	if (spc_lu_init(lu))
		return TGTADM_NOMEM;

	strncpy(lu->attrs.product_id, "VIRTUAL-TAPE",
		sizeof(lu->attrs.product_id));
	lu->attrs.version_desc[0] = 0x0200; /* SSC no version claimed */
	lu->attrs.version_desc[1] = 0x0960; /* iSCSI */
	lu->attrs.version_desc[2] = 0x0300; /* SPC-3 */
	lu->attrs.removable = 1;

	data = lu->mode_block_descriptor;
	size = lu->size >> BLK_SHIFT;

	*(uint32_t *)(data) = (size >> 32) ?
			__cpu_to_be32(0xffffffff) : __cpu_to_be32(size);
	*(uint32_t *)(data + 4) = __cpu_to_be32(1 << BLK_SHIFT);

	/* Vendor uniq - However most apps seem to call for mode page 0*/
	add_mode_page(lu, "0:0:0");
	/* Disconnect page */
	add_mode_page(lu, "2:0:14:0x80:0x80:0:0xa:0:0:0:0:0:0:0:0:0:0");
	/* Data Compression Page */
	add_mode_page(lu, "15:0:12:0:0:0:0:0:0:0:0:0:0:0:0");
	/* Device Configuration Page */
	add_mode_page(lu, "0x10:0:11:0:0:0:0:0:0:0:0:0x48:0:0");
	/* Control page */
	add_mode_page(lu, "10:0:10:2:0:0:0:0:0:0:0:2:0");
	/* Informational Exceptions Control page */
	add_mode_page(lu, "0x1c:0:10:8:0:0:0:0:0:0:0:0:0");

	return 0;
}

static struct device_type_template ssc_template = {
	.type		= TYPE_TAPE,
	.lu_init	= ssc_lu_init,
	.lu_config	= spc_lu_config,
	.lu_online	= spc_lu_online,
	.lu_offline	= spc_lu_offline,
	.lu_exit	= spc_lu_exit,

	.ops		= {
		{spc_test_unit,},
		{ssc_rw,},
		{spc_illegal_op,},
		{spc_request_sense,},
		{spc_illegal_op,},
		{ssc_read_block_limit,},
		{spc_illegal_op,},
		{spc_illegal_op,},

		{ssc_rw,},
		{spc_illegal_op,},
		{ssc_rw,},
		{ssc_rw,},
		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_illegal_op,},

		/* 0x10 */
		{ssc_rw,},
		{ssc_rw,},
		{spc_inquiry,},
		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_illegal_op,},

		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_mode_sense,},
		{spc_start_stop,},
		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_illegal_op,},

		/* 0x20 */
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
		{spc_illegal_op,},

		/* 0x30 */
		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_illegal_op,},
		{ssc_rw,},
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

		[0x40 ... 0x4f] = {spc_illegal_op,},

		/* 0x50 */
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
		{spc_mode_sense,},
		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_illegal_op,},

		[0x60 ... 0x7f] = {spc_illegal_op,},

		/* 0x80 */
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
		{spc_illegal_op,},

		/* 0x90 */
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
		{spc_illegal_op,},

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

__attribute__((constructor)) static void ssc_init(void)
{
	device_type_register(&ssc_template);
}
