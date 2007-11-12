/*
 * SCSI block command processing
 *
 * Copyright (C) 2004-2007 FUJITA Tomonori <tomof@acm.org>
 * Copyright (C) 2005-2007 Mike Christie <michaelc@cs.wisc.edu>
 *
 * This code is based on Ardis's iSCSI implementation.
 *   http://www.ardistech.com/iscsi/
 *   Copyright (C) 2002-2003 Ardis Technolgies <roman@ardistech.com>,
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

static int sbc_rw(int host_no, struct scsi_cmd *cmd)
{
	int ret;
	unsigned char key = ILLEGAL_REQUEST;
	uint16_t asc = ASC_LUN_NOT_SUPPORTED;

	ret = device_reserved(cmd);
	if (ret)
		return SAM_STAT_RESERVATION_CONFLICT;

	/* we need to set data dir for kernel drivers */
	switch (cmd->scb[0]) {
	case WRITE_6:
	case WRITE_10:
	case WRITE_16:
	case WRITE_VERIFY:
		scsi_set_data_dir(cmd, DATA_WRITE);
		break;
	default:
		scsi_set_data_dir(cmd, DATA_READ);
		break;
	}

	cmd->offset = (scsi_rw_offset(cmd->scb) << BLK_SHIFT);
	ret = cmd->dev->bst->bs_cmd_submit(cmd);
	if (ret) {
		key = HARDWARE_ERROR;
		asc = ASC_INTERNAL_TGT_FAILURE;
	} else {
		cmd->mmapped = 1;
		return SAM_STAT_GOOD;
	}

	cmd->offset = 0;
	cmd->len = 0;
	sense_data_build(cmd, key, asc);
	return SAM_STAT_CHECK_CONDITION;
}

static int sbc_reserve(int host_no, struct scsi_cmd *cmd)
{
	if (device_reserve(cmd))
		return SAM_STAT_RESERVATION_CONFLICT ;
	else
		return SAM_STAT_GOOD;
}

static int sbc_release(int host_no, struct scsi_cmd *cmd)
{
	int ret;

	ret = device_release(cmd->c_target->tid, cmd->cmd_itn_id,
			     cmd->dev->lun, 0);

	return ret ? SAM_STAT_RESERVATION_CONFLICT : SAM_STAT_GOOD;
}

static int sbc_read_capacity(int host_no, struct scsi_cmd *cmd)
{
	uint32_t *data;
	uint64_t size;
	uint8_t *scb = cmd->scb;
	unsigned char key = ILLEGAL_REQUEST;
	uint16_t asc = ASC_LUN_NOT_SUPPORTED;

	if (device_reserved(cmd))
		return SAM_STAT_RESERVATION_CONFLICT;

	if (!(scb[8] & 0x1) & (scb[2] | scb[3] | scb[4] | scb[5])) {
		asc = ASC_INVALID_FIELD_IN_CDB;
		goto sense;
	}

	data = scsi_get_read_buffer(cmd);
	size = cmd->dev->size >> BLK_SHIFT;

	data[0] = (size >> 32) ?
		__cpu_to_be32(0xffffffff) : __cpu_to_be32(size - 1);
	data[1] = __cpu_to_be32(1U << BLK_SHIFT);
	cmd->len = 8;

	return SAM_STAT_GOOD;
sense:
	cmd->len = 0;
	sense_data_build(cmd, key, asc);
	return SAM_STAT_CHECK_CONDITION;
}

static int sbc_sync_cache(int host_no, struct scsi_cmd *cmd)
{
	int ret, len;
	uint8_t key = ILLEGAL_REQUEST;
	uint16_t asc = ASC_LUN_NOT_SUPPORTED;

	if (device_reserved(cmd))
		return SAM_STAT_RESERVATION_CONFLICT;

	ret = cmd->dev->bst->bs_cmd_submit(cmd);
	switch (ret) {
	case EROFS:
	case EINVAL:
	case EBADF:
	case EIO:
		/*
		 * is this the right sense code?
		 * what should I put for the asc/ascq?
		 */
		key = HARDWARE_ERROR;
		asc = ASC_INTERNAL_TGT_FAILURE;
		goto sense;
	default:
		len = 0;
		return SAM_STAT_GOOD;
	}

sense:
	cmd->len = 0;
	sense_data_build(cmd, key, asc);
	return SAM_STAT_CHECK_CONDITION;
}

static int sbc_lu_init(struct scsi_lu *lu)
{
	uint64_t size;
	uint8_t *data;

	if (spc_lu_init(lu))
		return TGTADM_NOMEM;

	strncpy(lu->attrs.product_id, "VIRTUAL-DISK", sizeof(lu->attrs.product_id));
	lu->attrs.version_desc[0] = 0x04C0; /* SBC-3 no version claimed */
	lu->attrs.version_desc[1] = 0x0960; /* iSCSI */
	lu->attrs.version_desc[2] = 0x0300; /* SPC-3 */

	data = lu->mode_block_descriptor;
	size = lu->size >> BLK_SHIFT;

	*(uint32_t *)(data) = (size >> 32) ?
			__cpu_to_be32(0xffffffff) : __cpu_to_be32(size);
	*(uint32_t *)(data + 4) = __cpu_to_be32(1 << BLK_SHIFT);

	/* Vendor uniq - However most apps seem to call for mode page 0*/
	add_mode_page(lu, "0:0:0");
	/* Disconnect page */
	add_mode_page(lu, "2:0:14:0x80:0x80:0:0xa:0:0:0:0:0:0:0:0:0:0");
	/* Format page */
	add_mode_page(lu, "3:0:22:0:0:0:0:0:0:0:0:1:0:2:0:0:0:0:0:0:0:0:13:0:0");
	/* GEO page */
	add_mode_page(lu, "4:0:22:0:0:0:0x40:0:0:0:0:0:"
		      "0:0:0:0:0:0:0:0:0:0x3a:0x98:0:0");
	/* Caching Page */
	add_mode_page(lu, "8:0:18:0x14:0:0xff:0xff:0:0:"
		      "0xff:0xff:0xff:0xff:0x80:0x14:0:0:0:0:0:0");
	/* Control page */
	add_mode_page(lu, "10:0:10:2:0:0:0:0:0:0:0:2:0");
	/* Informational Exceptions Control page */
	add_mode_page(lu, "0x1c:0:10:8:0:0:0:0:0:0:0:0:0");

	return 0;
}

static struct device_type_template sbc_template = {
	.type		= TYPE_DISK,
	.lu_init	= sbc_lu_init,
	.lu_config	= spc_lu_config,
	.lu_exit	= spc_lu_exit,
	.ops		= {
		{spc_test_unit,},
		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_request_sense,},
		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_illegal_op,},

		{sbc_rw,},
		{spc_illegal_op,},
		{sbc_rw,},
		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_illegal_op,},

		/* 0x10 */
		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_inquiry,},
		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_illegal_op,},
		{sbc_reserve,},
		{sbc_release,},

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
		{sbc_read_capacity,},
		{spc_illegal_op,},
		{spc_illegal_op,},

		{sbc_rw},
		{spc_illegal_op,},
		{sbc_rw},
		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_illegal_op,},
		{sbc_rw},
		{spc_test_unit},

		/* 0x30 */
		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_illegal_op,},
		{sbc_sync_cache,},
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

		{sbc_rw,},
		{spc_illegal_op,},
		{sbc_rw,},
		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_illegal_op,},
		{sbc_rw},
		{spc_test_unit},

		/* 0x90 */
		{spc_illegal_op,},
		{sbc_sync_cache,},
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

		{sbc_rw,},
		{spc_illegal_op,},
		{sbc_rw,},
		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_illegal_op,},
		{sbc_rw,},
		{spc_test_unit,},

		[0xb0 ... 0xff] = {spc_illegal_op},
	}
};

__attribute__((constructor)) static void sbc_init(void)
{
	device_type_register(&sbc_template);
}
