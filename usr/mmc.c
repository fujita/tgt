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

#define PRODUCT_ID	"Virtual CD/DVD ROM"
#define PRODUCT_REV	"0"

static int mmc_inquiry(int host_no, struct scsi_cmd *cmd)
{
	int len, ret = SAM_STAT_CHECK_CONDITION;
	uint8_t *data;
	uint8_t *scb = cmd->scb;
	unsigned char key = ILLEGAL_REQUEST, asc = 0x24;

	if (((scb[1] & 0x3) == 0x3) || (!(scb[1] & 0x3) && scb[2]))
		goto sense;

	data = valloc(pagesize);
	if (!data) {
		key = HARDWARE_ERROR;
		asc = 0;
		goto sense;
	}
	memset(data, 0, pagesize);

	if (!(scb[1] & 0x3)) {
		data[0] = TYPE_ROM;
		data[1] = 0x80;
		data[2] = 0x03;
		data[3] = 0x02;
		data[4] = 0x1f;
		data[7] = 0x02;
		memcpy(data + 8, VENDOR_ID,
		       min_t(size_t, strlen(VENDOR_ID), 8));
		memcpy(data + 16, PRODUCT_ID,
			min_t(size_t, strlen(PRODUCT_ID), 16));
		memcpy(data + 32, PRODUCT_REV,
			min_t(size_t, strlen(PRODUCT_REV), 4));
		len = data[4] + 5;
		ret = SAM_STAT_GOOD;
	} else if (scb[1] & 0x2) {
		/* CmdDt bit is set */
		/* We do not support it now. */
	} else if (scb[1] & 0x1) {
		if (scb[2] == 0x0) {
			data[0] = TYPE_ROM;
			data[1] = 0x0;
			data[3] = 3;
			data[4] = 0x0;
			data[5] = 0x80;
			data[6] = 0x83;
			len = 7;
			ret = SAM_STAT_GOOD;
		} else if (scb[2] == 0x80) {
			int tmp = SCSI_SN_LEN;

			data[1] = 0x80;
			data[3] = SCSI_SN_LEN;
			memset(data + 4, 0x20, 4);
			len = SCSI_SN_LEN + 4;
			ret = SAM_STAT_GOOD;

			if (cmd->dev && strlen(cmd->dev->scsi_sn)) {
				uint8_t *p;
				char *q;

				p = data + 4 + tmp - 1;
				q = cmd->dev->scsi_sn + SCSI_SN_LEN - 1;

				for (; tmp > 0; tmp--, q)
					*(p--) = *q;
			}
		} else if (scb[2] == 0x83) {
			int tmp = SCSI_ID_LEN;

			data[1] = 0x83;
			data[3] = tmp + 4;
			data[4] = 0x1;
			data[5] = 0x1;
			data[7] = tmp;
			if (cmd->dev)
				strncpy((char *) data + 8, cmd->dev->scsi_id,
				        SCSI_ID_LEN);
			len = tmp + 8;
			ret = SAM_STAT_GOOD;
		}
	}

	if (ret != SAM_STAT_GOOD)
		goto sense;

	cmd->len = min_t(int, len, scb[4]);
	cmd->uaddr = (unsigned long) data;

	if (!cmd->dev)
		data[0] = TYPE_NO_LUN;

	return SAM_STAT_GOOD;
sense:
	cmd->len = 0;
	sense_data_build(cmd, key, asc, 0);
	return SAM_STAT_CHECK_CONDITION;
}

static int mmc_rw(int host_no, struct scsi_cmd *cmd)
{
	int ret;
	unsigned long uaddr;
	bkio_submit_t *submit = cmd->c_target->bdt->bd_cmd_submit;

	cmd->offset = (scsi_rw_offset(cmd->scb) << MMC_BLK_SHIFT);
	uaddr = cmd->uaddr;
	ret = submit(cmd->dev, cmd->scb, cmd->rw, cmd->len, &uaddr,
		     cmd->offset, &cmd->async, (void *)cmd);
	if (ret) {
		cmd->offset = 0;
		cmd->len = 0;
		sense_data_build(cmd, ILLEGAL_REQUEST, 0x25, 0);
		return SAM_STAT_CHECK_CONDITION;
	} else {
		cmd->mmapped = 1;
		cmd->uaddr = uaddr;
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
	uint8_t *data;

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
	.name	= "cdrom/dvd",
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
		{mmc_inquiry,},
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
