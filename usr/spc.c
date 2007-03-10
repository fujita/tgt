/*
 * SCSI primary command processing
 *
 * Copyright (C) 2005-2007 FUJITA Tomonori <tomof@acm.org>
 * Copyright (C) 2005-2007 Mike Christie <michaelc@cs.wisc.edu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "list.h"
#include "util.h"
#include "tgtd.h"
#include "target.h"
#include "driver.h"
#include "scsi.h"
#include "spc.h"

static int __spc_report_luns(int host_no, struct scsi_cmd *cmd)
{
	struct tgt_device *dev;
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
	list_for_each_entry(dev, dev_list, device_siblings) {
		nr_luns++;

		if (overflow)
			continue;

		lun = dev->lun;
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

int spc_report_luns(int host_no, struct scsi_cmd *cmd)
{
	struct target *target = cmd->c_target;
	int ret, lid = target->lid;

	/* temp hack */
	if (tgt_drivers[lid]->scsi_report_luns)
		ret = tgt_drivers[lid]->scsi_report_luns(host_no, cmd);
	else
		ret = __spc_report_luns(host_no, cmd);

	return ret;
}

int spc_start_stop(int host_no, struct scsi_cmd *cmd)
{
	cmd->len = 0;

	if (cmd->dev) {
		if (device_reserved(cmd->cmd_nexus_id, cmd->dev->lun, host_no))
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
		ret = device_reserved(cmd->cmd_nexus_id, cmd->dev->lun, host_no);
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

int spc_illegal_op(int host_no, struct scsi_cmd *cmd)
{
	cmd->len = 0;
	sense_data_build(cmd, ILLEGAL_REQUEST, 0x24, 0);
	return SAM_STAT_CHECK_CONDITION;
}
