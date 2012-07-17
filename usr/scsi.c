/*
 * SCSI lib functions
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
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <syscall.h>
#include <unistd.h>
#include <linux/fs.h>

#include "list.h"
#include "util.h"
#include "tgtd.h"
#include "target.h"
#include "driver.h"
#include "scsi.h"
#include "spc.h"

static unsigned char scsi_command_size[8] = {6, 10, 10, 12, 16, 12, 10, 10};

#define COMMAND_SIZE(opcode) scsi_command_size[((opcode) >> 5) & 7]
#define CDB_SIZE(cmd) (((((cmd)->scb[0] >> 5) & 7) < 6) ? \
				COMMAND_SIZE((cmd)->scb[0]) : (cmd)->scb_len)
#define CDB_CONTROL(cmd) (((cmd)->scb[0] == 0x7f) ? (cmd)->scb[1] \
			  : (cmd)->scb[CDB_SIZE((cmd))-1])

int get_scsi_command_size(unsigned char op)
{
	return COMMAND_SIZE(op);
}

int get_scsi_cdb_size(struct scsi_cmd *cmd)
{
	return CDB_SIZE(cmd);
}

void sense_data_build(struct scsi_cmd *cmd, uint8_t key, uint16_t asc)
{

	if (cmd->dev->attrs.sense_format) {
		/* descriptor format */
		cmd->sense_buffer[0] = 0x72;  /* current, not deferred */
		cmd->sense_buffer[1] = key;
		cmd->sense_buffer[2] = (asc >> 8) & 0xff;
		cmd->sense_buffer[3] = asc & 0xff;
		cmd->sense_len = 8;
	} else {
		/* fixed format */
		int len = 0xa;
		cmd->sense_buffer[0] = 0x70;  /* current, not deferred */
		cmd->sense_buffer[2] = key;
		cmd->sense_buffer[7] = len;
		cmd->sense_buffer[12] = (asc >> 8) & 0xff;
		cmd->sense_buffer[13] = asc & 0xff;
		cmd->sense_len = len + 8;
	}
}

#define        TGT_INVALID_DEV_ID      ~0ULL

static uint64_t __scsi_get_devid(uint8_t *p)
{
	uint64_t lun = TGT_INVALID_DEV_ID;

	switch (*p >> 6) {
	case 0:
		lun = p[1];
		break;
	case 1:
		lun = (0x3f & p[0]) << 8 | p[1];
		break;
	case 2:
	case 3:
	default:
		break;
	}

	return lun;
}

uint64_t scsi_get_devid(int lid, uint8_t *p)
{
	typeof(__scsi_get_devid) *fn;
	fn = tgt_drivers[lid]->scsi_get_lun ? : __scsi_get_devid;
	return fn(p);
}

uint64_t scsi_rw_offset(uint8_t *scb)
{
	uint64_t off;

	switch (scb[0]) {
	case READ_6:
	case WRITE_6:
		off = ((scb[1] & 0x1f) << 16) + (scb[2] << 8) + scb[3];
		break;
	case READ_10:
	case PRE_FETCH_10:
	case WRITE_10:
	case VERIFY_10:
	case WRITE_VERIFY:
	case WRITE_SAME:
	case SYNCHRONIZE_CACHE:
	case READ_12:
	case WRITE_12:
	case VERIFY_12:
	case WRITE_VERIFY_12:
		off = (uint32_t)scb[2] << 24 | (uint32_t)scb[3] << 16 |
			(uint32_t)scb[4] << 8 | (uint32_t)scb[5];
		break;
	case READ_16:
	case PRE_FETCH_16:
	case WRITE_16:
	case ORWRITE_16:
	case VERIFY_16:
	case WRITE_VERIFY_16:
	case WRITE_SAME_16:
	case SYNCHRONIZE_CACHE_16:
	case COMPARE_AND_WRITE:
		off = (uint64_t)scb[2] << 56 | (uint64_t)scb[3] << 48 |
			(uint64_t)scb[4] << 40 | (uint64_t)scb[5] << 32 |
			(uint64_t)scb[6] << 24 | (uint64_t)scb[7] << 16 |
			(uint64_t)scb[8] << 8 | (uint64_t)scb[9];
		break;
	default:
		off = 0;
		break;
	}

	return off;
}

uint32_t scsi_rw_count(uint8_t *scb)
{
	uint32_t cnt;

	switch (scb[0]) {
	case READ_6:
	case WRITE_6:
		cnt = scb[4];
		if (!cnt)
			cnt = 256;
		break;
	case READ_10:
	case PRE_FETCH_10:
	case WRITE_10:
	case VERIFY_10:
	case WRITE_VERIFY:
	case WRITE_SAME:
	case SYNCHRONIZE_CACHE:
		cnt = (uint16_t)scb[7] << 8 | (uint16_t)scb[8];
		break;
	case READ_12:
	case WRITE_12:
	case VERIFY_12:
	case WRITE_VERIFY_12:
		cnt = (uint32_t)scb[6] << 24 | (uint32_t)scb[7] << 16 |
			(uint32_t)scb[8] << 8 | (uint32_t)scb[9];
		break;
	case READ_16:
	case PRE_FETCH_16:
	case WRITE_16:
	case ORWRITE_16:
	case VERIFY_16:
	case WRITE_VERIFY_16:
	case WRITE_SAME_16:
	case SYNCHRONIZE_CACHE_16:
		cnt = (uint32_t)scb[10] << 24 | (uint32_t)scb[11] << 16 |
			(uint32_t)scb[12] << 8 | (uint32_t)scb[13];
		break;
	case COMPARE_AND_WRITE:
		cnt = (uint32_t)scb[13];
		break;
	default:
		cnt = 0;
		break;
	}

	return cnt;
}

int scsi_cmd_perform(int host_no, struct scsi_cmd *cmd)
{
	int ret;
	unsigned char op = cmd->scb[0];
	struct it_nexus_lu_info *itn_lu;

	if (scsi_get_data_dir(cmd) == DATA_WRITE) {
		cmd->itn_lu_info->stat.wr_subm_bytes += scsi_get_out_length(cmd);
		cmd->itn_lu_info->stat.wr_subm_cmds++;
	} else if (scsi_get_data_dir(cmd) == DATA_READ) {
		cmd->itn_lu_info->stat.rd_subm_bytes += scsi_get_in_length(cmd);
		cmd->itn_lu_info->stat.rd_subm_cmds++;
	} else if (scsi_get_data_dir(cmd) == DATA_BIDIRECTIONAL) {
		cmd->itn_lu_info->stat.wr_subm_bytes += scsi_get_out_length(cmd);
		cmd->itn_lu_info->stat.rd_subm_bytes += scsi_get_in_length(cmd);
		cmd->itn_lu_info->stat.bidir_subm_cmds++;
	}

	if (CDB_CONTROL(cmd) & ((1U << 0) | (1U << 2))) {
		/*
		 * We don't support a linked command. SAM-3 say that
		 * it's optional. It's obsolete in SAM-4.
		 */

		/*
		 * We don't support ACA. SAM-3 and SAM-4 say that a
		 * logical unit MAY support ACA.
		 */
		sense_data_build(cmd,
				 ILLEGAL_REQUEST, ASC_INVALID_FIELD_IN_CDB);
		return SAM_STAT_CHECK_CONDITION;
	}

	if (cmd->dev->lun != cmd->dev_id) {
		switch (op) {
		case INQUIRY:
			break;
		case REQUEST_SENSE:
			sense_data_build(cmd, ILLEGAL_REQUEST, ASC_LUN_NOT_SUPPORTED);
			return SAM_STAT_GOOD;
		default:
			sense_data_build(cmd, ILLEGAL_REQUEST, ASC_LUN_NOT_SUPPORTED);
			return SAM_STAT_CHECK_CONDITION;
		}
	}

	/* check out Unit Attention condition */
	switch (op) {
	case INQUIRY:
		break;
	case REPORT_LUNS:
		list_for_each_entry(itn_lu,
				    &cmd->it_nexus->itn_itl_info_list,
				    itn_itl_info_siblings)
			ua_sense_clear(itn_lu,
				       ASC_REPORTED_LUNS_DATA_HAS_CHANGED);
		break;
	case REQUEST_SENSE:
		ret = ua_sense_del(cmd, 0);
		if (!ret)
			return SAM_STAT_CHECK_CONDITION;
		break;
	default:
		/* FIXME: use UA_INTLCK_CTRL field. */
		ret = ua_sense_del(cmd, 1);
		if (!ret)
			return SAM_STAT_CHECK_CONDITION;
	}

	if (spc_access_check(cmd))
		return SAM_STAT_RESERVATION_CONFLICT;

	return cmd->dev->dev_type_template.ops[op].cmd_perform(host_no, cmd);
}

int scsi_is_io_opcode(unsigned char op)
{
	int ret = 0;

	switch (op) {
	case READ_6:
	case WRITE_6:
	case READ_10:
	case WRITE_10:
	case VERIFY_10:
	case WRITE_VERIFY:
	case READ_12:
	case WRITE_12:
	case VERIFY_12:
	case WRITE_VERIFY_12:
	case READ_16:
	case WRITE_16:
	case ORWRITE_16:
	case VERIFY_16:
	case WRITE_VERIFY_16:
	case COMPARE_AND_WRITE:
		ret = 1;
		break;
	default:
		break;
	}
	return ret;
}

/* this isn't complete but good enough for what kernel drivers need */

enum data_direction scsi_data_dir_opcode(unsigned char op)
{
	enum data_direction dir;

	switch (op) {
	case WRITE_6:
	case WRITE_10:
	case WRITE_12:
	case WRITE_16:
	case ORWRITE_16:
	case WRITE_VERIFY:
	case WRITE_VERIFY_12:
	case WRITE_VERIFY_16:
	case COMPARE_AND_WRITE:
		dir = DATA_WRITE;
		break;
	default:
		dir = DATA_READ;
		break;
	}

	return dir;
}
