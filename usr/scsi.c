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
	case WRITE_10:
	case VERIFY:
	case WRITE_VERIFY:
	case SYNCHRONIZE_CACHE:
	case READ_12:
	case WRITE_12:
	case VERIFY_12:
	case WRITE_VERIFY_12:
		off = (uint32_t)scb[2] << 24 | (uint32_t)scb[3] << 16 |
			(uint32_t)scb[4] << 8 | (uint32_t)scb[5];
		break;
	case READ_16:
	case WRITE_16:
	case VERIFY_16:
	case WRITE_VERIFY_16:
	case SYNCHRONIZE_CACHE_16:
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

int scsi_cmd_perform(int host_no, struct scsi_cmd *cmd)
{
	unsigned char op = cmd->scb[0];

	if (cmd->scb[CDB_SIZE(cmd) - 1] & (1U << 2)) {
		/*
		 * We don't support ACA. SAM-3 and SAM-4 say that a
		 * logical unit MAY support ACA.
		 */
		sense_data_build(cmd,
				 ILLEGAL_REQUEST, ASC_INVALID_FIELD_IN_CDB);
		return SAM_STAT_CHECK_CONDITION;
	}

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
	case VERIFY:
	case WRITE_VERIFY:
	case READ_12:
	case WRITE_12:
	case VERIFY_12:
	case WRITE_VERIFY_12:
	case READ_16:
	case WRITE_16:
	case VERIFY_16:
	case WRITE_VERIFY_16:
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
	case WRITE_VERIFY:
	case WRITE_12:
	case WRITE_16:
		dir = DATA_WRITE;
		break;
	default:
		dir = DATA_READ;
		break;
	}

	return dir;
}
