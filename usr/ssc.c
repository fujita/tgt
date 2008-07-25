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
#include "ssc.h"
#include "tgtadm_error.h"

#define BLK_SHIFT	9
#define GRANULARITY	9

#define MAX_BLK_SIZE	1048576
#define MIN_BLK_SIZE	4

static int ssc_rw(int host_no, struct scsi_cmd *cmd)
{
	int ret;
	unsigned char key = ILLEGAL_REQUEST;
	uint16_t asc = ASC_LUN_NOT_SUPPORTED;

	ret = device_reserved(cmd);
	if (ret)
		return SAM_STAT_RESERVATION_CONFLICT;

	cmd->scsi_cmd_done = target_cmd_io_done;

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

#define READ_BLK_LIMITS_SZ	6
static int ssc_read_block_limit(int host_no, struct scsi_cmd *cmd)
{
	struct ssc_info *ssc = dtype_priv(cmd->dev);
	uint8_t buf[READ_BLK_LIMITS_SZ];

	memset(buf, 0, sizeof(buf));

	if (ssc->blk_sz) {	/* Fixed block size */
		buf[0] = GRANULARITY;
		buf[1] = (ssc->blk_sz >> 16) & 0xff;
		buf[2] = (ssc->blk_sz >> 8) & 0xff;
		buf[3] = ssc->blk_sz & 0xff;
		buf[4] = (ssc->blk_sz >> 8) & 0xff;
		buf[5] = ssc->blk_sz & 0xff;
	} else {	/* Variable block size */
		buf[0] = GRANULARITY;
		buf[1] = (MAX_BLK_SIZE >> 16) & 0xff;
		buf[2] = (MAX_BLK_SIZE >> 8) & 0xff;
		buf[3] = MAX_BLK_SIZE & 0xff;
		buf[4] = (MIN_BLK_SIZE >> 8) & 0xff;
		buf[5] = MIN_BLK_SIZE & 0xff;
	}

	memcpy(scsi_get_in_buffer(cmd), buf, READ_BLK_LIMITS_SZ);
	eprintf("In ssc_read_block_limit \n");
	return SAM_STAT_GOOD;
}

static int ssc_lu_init(struct scsi_lu *lu)
{
	uint8_t *data;
	struct ssc_info *ssc;

	ssc = zalloc(sizeof(struct ssc_info));
	if (ssc)
		dtype_priv(lu) = ssc;
	else
		return -ENOMEM;

	if (spc_lu_init(lu))
		return TGTADM_NOMEM;

	strncpy(lu->attrs.product_id, "VIRTUAL-TAPE",
		sizeof(lu->attrs.product_id));
	lu->attrs.version_desc[0] = 0x0200; /* SSC no version claimed */
	lu->attrs.version_desc[1] = 0x0960; /* iSCSI */
	lu->attrs.version_desc[2] = 0x0300; /* SPC-3 */
	lu->attrs.removable = 1;

	data = lu->mode_block_descriptor;
	ssc->blk_sz = 1 << BLK_SHIFT;

	/* SSC devices do not need to set number of blks */
	*(uint32_t *)(data) = 0;

	/* Set default blk size */
	*(uint32_t *)(data + 4) = __cpu_to_be32(ssc->blk_sz);

	/* Vendor uniq - However most apps seem to call for mode page 0*/
	add_mode_page(lu, "0:0:0");
	/* Read-Write Error Recovery - Mandatory - SSC3 8.3.5 */
	add_mode_page(lu, "1:0:10:0:8:0:0:0:0:8:0:0:0");
	/* Disconnect page - Mandatory - SPC-4 */
	add_mode_page(lu, "2:0:14:0x80:0x80:0:0xa:0:0:0:0:0:0:0:0:0:0");
	/* Control page - Mandatory - SPC-4 */
	add_mode_page(lu, "10:0:10:2:0:0:0:0:0:0:0:2:0");
	/* Data Compression - Mandatory - SSC3 8.3.2 */
	add_mode_page(lu, "15:0:14:0:0:0:0:0:0:0:0:0:0:0:0:0:0");
	/* Device Configuration - Mandatory - SSC3 8.3.3 */
	add_mode_page(lu, "16:0:14:0:0:0:128:128:0:0:0:0:0:0:0:0:0");
	/* Informational Exceptions Control page - Mandatory - SSC3 8.3.6 */
	add_mode_page(lu, "0x1c:0:10:8:0:0:0:0:0:0:0:0:0");
	/* Medium Configuration - Mandatory - SSC3 8.3.7 */
	add_mode_page(lu, "0x1d:0:0x1e:1:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0"
				":0:0:0:0:0:0:0:0:0:0:0:0:0");
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
