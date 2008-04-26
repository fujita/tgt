/*
 * SCSI multimedia command processing
 *
 * Copyright (C) 2007 FUJITA Tomonori <tomof@acm.org>
 * Copyright (C) 2007 Mike Christie <michaelc@cs.wisc.edu>
 *
 * This code is based on Ardis's iSCSI implementation.
 *   http://www.ardistech.com/iscsi/
 *   Copyright (C) 2002-2003 Ardis Technolgies <roman@ardistech.com>
 *
 * This code is also based on Ming's mmc work for IET.
 * Copyright (C) 2005-2007 Ming Zhang <blackmagic02881@gmail.com>
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
#include "target.h"
#include "tgtadm_error.h"
#include "driver.h"
#include "scsi.h"
#include "spc.h"
#include "tgtadm_error.h"

#define MMC_BLK_SHIFT 11

static int mmc_rw(int host_no, struct scsi_cmd *cmd)
{
	int ret;

	cmd->scsi_cmd_done = target_cmd_io_done;

	cmd->offset = (scsi_rw_offset(cmd->scb) << MMC_BLK_SHIFT);
	ret = cmd->dev->bst->bs_cmd_submit(cmd);
	if (ret) {
		cmd->offset = 0;
		if (scsi_get_data_dir(cmd) == DATA_WRITE)
			scsi_set_out_resid_by_actual(cmd, 0);
		else
			scsi_set_in_resid_by_actual(cmd, 0);

		sense_data_build(cmd, ILLEGAL_REQUEST, ASC_LUN_NOT_SUPPORTED);
		return SAM_STAT_CHECK_CONDITION;
	} else {
		set_cmd_mmapio(cmd);
		return SAM_STAT_GOOD;
	}
	return 0;
}

static int mmc_read_toc(int host_no, struct scsi_cmd *cmd)
{
	uint8_t *data;
	uint8_t buf[16];

	memset(buf, 0, sizeof(buf));
	data = buf;

	/* forged for single session data cd only. all iso file fall into this */
	if (cmd->scb[1] & 0x2) {
		data[1] = 0x12;
		data[2] = 0x01;
		data[3] = 0x01;
		data[5] = 0x14;
		data[6] = 0x01;
		data[13] = 0x14;
		data[14] = 0xaa;
	} else {
		data[1] = 0x0a;
		data[2] = 0x01;
		data[3] = 0x01;
		data[5] = 0x14;
		data[6] = 0x01;
	}

	memcpy(scsi_get_in_buffer(cmd), data,
	       min(scsi_get_in_length(cmd), (uint32_t) sizeof(buf)));

	scsi_set_in_resid_by_actual(cmd, data[1] + 2);

	return SAM_STAT_GOOD;
}

static int mmc_read_capacity(int host_no, struct scsi_cmd *cmd)
{
	uint64_t size;
	uint32_t *data;

	if (scsi_get_in_length(cmd) < 8)
		goto overflow;

	data = scsi_get_in_buffer(cmd);
	size = cmd->dev->size >> MMC_BLK_SHIFT;

	data[0] = (size >> 32) ?
		__cpu_to_be32(0xffffffff) : __cpu_to_be32(size - 1);
	data[1] = __cpu_to_be32(1U << MMC_BLK_SHIFT);

overflow:
	scsi_set_in_resid_by_actual(cmd, 8);
	return SAM_STAT_GOOD;
}

static int mmc_mode_sense(int host_no, struct scsi_cmd *cmd)
{
	uint8_t *scb = cmd->scb;

	/* MMC devices always return descriptor block */
	scb[1] |= 8;
	return spc_mode_sense(host_no, cmd);
}

static int mmc_lu_init(struct scsi_lu *lu)
{
	if (spc_lu_init(lu))
		return TGTADM_NOMEM;

	strncpy(lu->attrs.product_id, "VIRTUAL-CDROM", sizeof(lu->attrs.product_id));
	lu->attrs.sense_format = 0;
	lu->attrs.version_desc[0] = 0x02A0; /* MMC3, no version claimed */
	lu->attrs.version_desc[1] = 0x0960; /* iSCSI */
	lu->attrs.version_desc[2] = 0x0300; /* SPC-3 */

	lu->attrs.removable = 1;

	/*
	 * Set up default mode pages
	 * Ref: mmc6r00.pdf 7.2.2 (Table 649)
	 */

	/* Vendor uniq - However most apps seem to call for mode page 0*/
	add_mode_page(lu, "0:0:0");
	/* Read/Write Error Recovery */
	add_mode_page(lu, "1:0:10:0:8:0:0:0:0:8:0:0:0");
	/* MRW */
	add_mode_page(lu, "3:0:6:0:0:0:0:0:0");
	/* Write Parameter
	 * Somebody who knows more about this mode page should be setting
	 * defaults.
	add_mode_page(lu, "5:0:0");
	 */
	/* Caching Page */
	add_mode_page(lu, "8:0:10:0:0:0:0:0:0:0:0:0:0");
	/* Control page */
	add_mode_page(lu, "10:0:10:2:0:0:0:0:0:0:0:2:0");
	/* Power Condition */
	add_mode_page(lu, "0x1a:0:10:8:0:0:0:0:0:0:0:0:0");
	/* Informational Exceptions Control page */
	add_mode_page(lu, "0x1c:0:10:8:0:0:0:0:0:0:0:0:0");
	/* Timeout & Protect */
	add_mode_page(lu, "0x1d:0:10:0:0:7:0:0:2:0:2:0:20");

	return 0;
}

static struct device_type_template mmc_template = {
	.type		= TYPE_ROM,
	.lu_init	= mmc_lu_init,
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

		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_illegal_op,},
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
		{spc_illegal_op,},
		{spc_illegal_op,},

		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_start_stop,},
		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_start_stop,}, /* allow medium removal */
		{spc_illegal_op,},

		/* 0x20 */
		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_illegal_op,},
		{mmc_read_capacity,},
		{spc_illegal_op,},
		{spc_illegal_op,},

		{mmc_rw},
		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_test_unit},

		[0x30 ... 0x3f] = {spc_illegal_op,},

		/* 0x40 */
		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_illegal_op,},
		{mmc_read_toc,},
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
		{mmc_mode_sense,},
		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_illegal_op,},
		{spc_illegal_op,},

		[0x60 ... 0x9f] = {spc_illegal_op,},

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

__attribute__((constructor)) static void mmc_init(void)
{
	device_type_register(&mmc_template);
}
