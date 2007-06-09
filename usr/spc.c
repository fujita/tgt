/*
 * SCSI primary command processing
 *
 * Copyright (C) 2005-2007 FUJITA Tomonori <tomof@acm.org>
 * Copyright (C) 2005-2007 Mike Christie <michaelc@cs.wisc.edu>
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

#include "list.h"
#include "util.h"
#include "tgtd.h"
#include "parser.h"
#include "target.h"
#include "driver.h"
#include "tgtadm_error.h"
#include "scsi.h"
#include "spc.h"

#define PRODUCT_REV	"0"
#define BLK_SHIFT	9

int spc_inquiry(int host_no, struct scsi_cmd *cmd)
{
	int len, ret = SAM_STAT_CHECK_CONDITION;
	uint8_t *data;
	uint8_t *scb = cmd->scb;
	unsigned char device_type = cmd->c_target->dev_type_template.type;
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

	dprintf("%x %x\n", scb[1], scb[2]);

	if (!(scb[1] & 0x3) && cmd->dev) {
		int i;
		uint16_t *desc;

		data[0] = device_type;
		data[1] = (cmd->dev->attrs->is_removable) ? 0x80 : 0;
		data[2] = 5;	/* SPC-3 */
		data[3] = 0x42;
		data[7] = 0x02;

		memset(data + 8, 0x20, 28);
		strncpy((char *)data + 8, cmd->dev->attrs->vendor_id, 8);
		strncpy((char *)data + 16, cmd->dev->attrs->product_id, 16);
		strncpy((char *)data + 32, cmd->dev->attrs->product_rev, 4);

		desc = (uint16_t *)(data + 58);
		for (i = 0; i < ARRAY_SIZE(cmd->dev->attrs->version_desc); i++)
			*desc++ = __cpu_to_be16(cmd->dev->attrs->version_desc[i]);

		len = 66;
		data[4] = len - 5;	/* Additional Length */
		ret = SAM_STAT_GOOD;
	} else if (scb[1] & 0x2) {
		/* CmdDt bit is set */
		/* We do not support it now. */
		data[1] = 0x1;
		data[5] = 0;
		len = 6;
		ret = SAM_STAT_GOOD;
	} else if (scb[1] & 0x1) {
		/* EVPD bit set */
		if (scb[2] == 0x0) {
			data[0] = device_type;
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
			len = 4 + SCSI_SN_LEN;
			ret = SAM_STAT_GOOD;

			if (cmd->dev && strlen(cmd->dev->attrs->scsi_sn)) {
				uint8_t *p;
				char *q;

				p = data + 4 + tmp - 1;
				q = cmd->dev->attrs->scsi_sn + SCSI_SN_LEN - 1;
				for (; tmp > 0; tmp--, q)
					*(p--) = *(q--);
			}
		} else if (scb[2] == 0x83) {
			int tmp = SCSI_ID_LEN;

			data[1] = 0x83;
			data[3] = tmp + 4;
			data[4] = 0x1;
			data[5] = 0x1;
			data[7] = tmp;
			if (cmd->dev)
				strncpy((char *) data + 8,
					cmd->dev->attrs->scsi_id, SCSI_ID_LEN);

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

int spc_report_luns(int host_no, struct scsi_cmd *cmd)
{
	struct scsi_lu *lu;
	struct list_head *dev_list = &cmd->c_target->device_list;
	uint64_t lun, *data;
	int idx, alen, oalen, nr_luns, rbuflen = 4096, overflow;
	unsigned char key = ILLEGAL_REQUEST, asc = 0x24;

	alen = __be32_to_cpu(*(uint32_t *)&cmd->scb[6]);
	if (alen < 16)
		goto sense;

	data = valloc(pagesize);
	if (!data) {
		key = HARDWARE_ERROR;
		asc = 0;
		goto sense;
	}
	memset(data, 0, pagesize);

	alen &= ~(8 - 1);
	oalen = alen;

	alen -= 8;
	rbuflen -= 8; /* FIXME */
	idx = 1;
	nr_luns = 0;

	overflow = 0;
	list_for_each_entry(lu, dev_list, device_siblings) {
		nr_luns++;

		if (overflow)
			continue;

		lun = lu->lun;
		lun = ((lun > 0xff) ? (0x1 << 30) : 0) | ((0x3ff & lun) << 16);
		data[idx++] = __cpu_to_be64(lun << 32);
		if (!(alen -= 8))
			overflow = 1;
		if (!(rbuflen -= 8)) {
			fprintf(stderr, "FIXME: too many luns\n");
			exit(-1);
		}
	}

	cmd->uaddr = (unsigned long)data;
	*((uint32_t *) data) = __cpu_to_be32(nr_luns * 8);
	cmd->len = min(oalen, nr_luns * 8 + 8);
	return SAM_STAT_GOOD;
sense:
	cmd->len = 0;
	sense_data_build(cmd, key, asc, 0);
	return SAM_STAT_CHECK_CONDITION;
}

int spc_start_stop(int host_no, struct scsi_cmd *cmd)
{
	cmd->len = 0;

	if (cmd->dev) {
		if (device_reserved(cmd))
			return SAM_STAT_RESERVATION_CONFLICT;
	} else {
		sense_data_build(cmd, ILLEGAL_REQUEST, 0x25, 0);
		return SAM_STAT_CHECK_CONDITION;
	}
	return SAM_STAT_GOOD;
}

int spc_test_unit(int host_no, struct scsi_cmd *cmd)
{
	int ret = SAM_STAT_GOOD;

	/* how should we test a backing-storage file? */

	if (cmd->dev) {
		ret = device_reserved(cmd);
		if (ret)
			ret = SAM_STAT_RESERVATION_CONFLICT;
	} else {
		cmd->len = 0;
		sense_data_build(cmd, ILLEGAL_REQUEST, 0x24, 0);
		ret = SAM_STAT_CHECK_CONDITION;
	}
	return ret;
}

int spc_request_sense(int host_no, struct scsi_cmd *cmd)
{
	cmd->len = 0;
	sense_data_build(cmd, NO_SENSE, 0, 0);
	return SAM_STAT_GOOD;
}

void dump_cdb(struct scsi_cmd *cmd)
{
	uint8_t *cdb = cmd->scb;

	switch(cmd->scb_len) {
	case 6:
		dprintf("SCSI CMD: %02x %02x %02x %02x %02d %02x",
			cdb[0], cdb[1], cdb[2], cdb[3], cdb[4], cdb[5]);
		break;
	case 10:
		dprintf("SCSI CMD: %02x %02x %02x %02x %02d %02x"
				" %02x %02x %02x %02x",
			cdb[0], cdb[1], cdb[2], cdb[3], cdb[4], cdb[5],
			cdb[6], cdb[7], cdb[8], cdb[9]);
		break;
	case 12:
		dprintf("SCSI CMD: %02x %02x %02x %02x %02d %02x"
				" %02x %02x %02x %02x %02x %02x",
			cdb[0], cdb[1], cdb[2], cdb[3], cdb[4], cdb[5],
			cdb[6], cdb[7], cdb[8], cdb[9], cdb[10], cdb[11]);
		break;
	case 16:
		dprintf("SCSI CMD: %02x %02x %02x %02x %02d %02x"
				" %02x %02x %02x %02x %02x %02x"
				" %02x %02x %02x %02x",
			cdb[0], cdb[1], cdb[2], cdb[3], cdb[4], cdb[5],
			cdb[6], cdb[7], cdb[8], cdb[9], cdb[10], cdb[11],
			cdb[12], cdb[13], cdb[14], cdb[15]);
		break;
	}
}

int spc_illegal_op(int host_no, struct scsi_cmd *cmd)
{
	dump_cdb(cmd);
	cmd->len = 0;
	sense_data_build(cmd, ILLEGAL_REQUEST, 0x20, 0);
	return SAM_STAT_CHECK_CONDITION;
}

enum {
	Opt_scsiid, Opt_scsisn, Opt_err,
};

static match_table_t tokens = {
	{Opt_scsiid, "scsi_id=%s"},
	{Opt_scsisn, "scsi_sn=%s"},
	{Opt_err, NULL},
};

int spc_lu_config(struct scsi_lu *lu, char *params) {
	int err = 0;
	char *p;

	if (!strncmp("targetOps", params, 9))
		params = params + 10;

	while ((p = strsep(&params, ",")) != NULL) {
		substring_t args[MAX_OPT_ARGS];
		int token;
		if (!*p)
			continue;
		dprintf("*p : %s\n", p);
		token = match_token(p, tokens, args);
		switch (token) {
		case Opt_scsiid:
			match_strncpy(lu->attrs->scsi_id, &args[0],
				      sizeof(lu->attrs->scsi_id) - 1);
			break;
		case Opt_scsisn:
			match_strncpy(lu->attrs->scsi_sn, &args[0],
				      sizeof(lu->attrs->scsi_sn) - 1);
			break;
		default:
			err = TGTADM_INVALID_REQUEST;
		}
	}
	return err;
}

int spc_lu_init(struct scsi_lu *lu)
{
	lu->attrs = zalloc(sizeof(struct lu_phy_attr));
	if (!lu->attrs)
		return -ENOMEM;

	memcpy(lu->attrs->vendor_id, VENDOR_ID, 8);
	memcpy(lu->attrs->product_rev, "0001", 4);
	lu->attrs->is_removable = 0;
	lu->attrs->sense_format = 0;
	lu->attrs->online = 0;
	lu->attrs->reset = 1;

	return 0;
}
