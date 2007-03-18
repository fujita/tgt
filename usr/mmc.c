/*
 * SCSI multimedia command processing
 *
 * (C) 2007 FUJITA Tomonori <tomof@acm.org>
 * (C) 2007 Mike Christie <michaelc@cs.wisc.edu>
 *
 * based on Ardis's iSCSI implementation.
 *
 * (C) 2005-2007 Ming Zhang <blackmagic02881@gmail.com>
 * This code is licenced under the GPL.
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
#include "driver.h"
#include "scsi.h"
#include "spc.h"

#define MMC_BLK_SHIFT 11

static int mmc_rw(int host_no, struct scsi_cmd *cmd)
{
	int ret;

	cmd->offset = (scsi_rw_offset(cmd->scb) << MMC_BLK_SHIFT);
	ret = cmd->c_target->bst->bs_cmd_submit(cmd);
	if (ret) {
		cmd->offset = 0;
		cmd->len = 0;
		sense_data_build(cmd, ILLEGAL_REQUEST, 0x25, 0);
		return SAM_STAT_CHECK_CONDITION;
	} else {
		cmd->mmapped = 1;
		return SAM_STAT_GOOD;
	}
	return 0;
}

static int mmc_read_toc(int host_no, struct scsi_cmd *cmd)
{
	uint8_t *data;

	data = valloc(pagesize);
	if (!data) {
		cmd->len = 0;
		sense_data_build(cmd, HARDWARE_ERROR, 0, 0);
		return SAM_STAT_CHECK_CONDITION;
	}
	memset(data, pagesize, 0);
	cmd->uaddr = (unsigned long) data;

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

	cmd->len = data[1] + 2;

	return SAM_STAT_GOOD;
}

static int mmc_read_capacity(int host_no, struct scsi_cmd *cmd)
{
	uint64_t size;
	uint32_t *data;

	data = valloc(pagesize);
	if (!data) {
		cmd->len = 0;
		sense_data_build(cmd, HARDWARE_ERROR, 0, 0);
		return SAM_STAT_CHECK_CONDITION;
	}
	memset(data, pagesize, 0);
	cmd->uaddr = (unsigned long) data;

	size = cmd->dev->size >> MMC_BLK_SHIFT;

	data[0] = (size >> 32) ?
		__cpu_to_be32(0xffffffff) : __cpu_to_be32(size - 1);
	data[1] = __cpu_to_be32(1U << MMC_BLK_SHIFT);
	cmd->len = 8;

	return SAM_STAT_GOOD;
}

struct device_type_template mmc_template = {
	.type	= TYPE_ROM,
	.name	= "cdrom/dvd",
	.pid	= "VIRTUAL-CDROM",
	.ops	= {
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

		[0x50 ... 0x9f] = {spc_illegal_op,},

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
