/*
 * SCSI object storage device command processing
 *
 * Copyright (C) 2006-2007 Pete Wyckoff <pw@osc.edu>
 * Copyright (C) 2007 FUJITA Tomonori <tomof@acm.org>
 * Copyright (C) 2007 Mike Christie <michaelc@cs.wisc.edu>
 *
 * Released under the terms of the GNU GPL v2.0.
 */

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

#define PRODUCT_ID	"OSD"
#define PRODUCT_REV	"0"

static int osd_inquiry(int host_no, struct scsi_cmd *cmd)
{
	uint8_t *data, *scb = cmd->scb;
	int len, ret = SAM_STAT_CHECK_CONDITION;
	unsigned char key = ILLEGAL_REQUEST, asc = 0x25;

	/* EVPD means need a page code */
	if ((scb[1] & 0x3) == 0 && scb[2] != 0)
		goto sense;

	data = valloc(pagesize);
	if (!data) {
		key = HARDWARE_ERROR;
		asc = 0;
		goto sense;
	}
	memset(data, 0, pagesize);

	dprintf("%x %x\n", scb[1], scb[2]);

	data[0] = TYPE_OSD;
	if (!cmd->dev)
		data[0] = TYPE_NO_LUN;

	if ((scb[1] & 0x1) == 0) {
		data[2] = 5;  /* modern version */
		data[3] = 0x02;  /* modern response format */
		data[7] = 0x02;  /* support command queueing */
		memset(data + 8, 0x20, 28);
		memcpy(data + 8,
		       VENDOR_ID, min_t(size_t, strlen(VENDOR_ID), 8));
		memcpy(data + 16,
		       PRODUCT_ID, min_t(size_t, strlen(PRODUCT_ID), 16));
		memcpy(data + 32,
		       PRODUCT_REV, min_t(size_t, strlen(PRODUCT_REV), 4));
		len = 36;
		if (cmd->dev) {
			data[58] = 0x03;
			data[59] = 0x40;  /* osd */
			data[60] = 0x09;
			data[61] = 0x60;  /* iscsi */
			data[62] = 0x03;
			data[63] = 0x00;  /* spc3 */
			len = 64;
		}
		data[4] = len - 5;  /* additional length */
		ret = SAM_STAT_GOOD;
	} else {
		if (!cmd->dev)
			goto sense;

		data[1] = scb[2];
		if (scb[2] == 0x0) {
			/* supported VPD pages */
			data[3] = 3;
			data[4] = 0x0;
			data[5] = 0x80;
			data[6] = 0x83;
			len = 7;
			ret = SAM_STAT_GOOD;
		} else if (scb[2] == 0x80) {
			/* unit serial number "    " */
			data[3] = 4;
			memset(data + 4, 0x20, 4);
			len = 8;
			ret = SAM_STAT_GOOD;
		} else if (scb[2] == 0x83) {
			/* device identification */
			data[3] = SCSI_ID_LEN + 4;
			data[4] = 0x1;
			data[5] = 0x1;
			data[7] = SCSI_ID_LEN;
			if (cmd->dev)
				memcpy(data + 8, cmd->dev->scsi_id, SCSI_ID_LEN);
			len = SCSI_ID_LEN + 8;
			ret = SAM_STAT_GOOD;
		}
	}

	if (ret != SAM_STAT_GOOD)
		goto sense;

	cmd->len = min_t(int, len, scb[4]);

	return SAM_STAT_GOOD;
sense:
	sense_data_build(cmd, key, asc, 0);
	cmd->len = 0;
	return SAM_STAT_CHECK_CONDITION;
}

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

	return cmd->c_target->bst->bs_cmd_submit(cmd);
}

static void device_osd_init(struct tgt_device *dev)
{
	dev->d_sense = 1;
}

struct device_type_template osd_template = {
	.type		= TYPE_OSD,
	.name		= "osd",
	.device_init	= device_osd_init,
	.ops		= {
		[0x00 ... 0x0f] = {spc_illegal_op},

		/* 0x10 */
		{spc_illegal_op,},
		{spc_illegal_op,},
		{osd_inquiry,},
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

		[0x80 ... 0xff] = {spc_illegal_op},
	}
};
