/*
 * SCSI command processing
 *
 * (C) 2004 - 2005 FUJITA Tomonori <tomof@acm.org>
 * (C) 2005 Mike Christie <michaelc@cs.wisc.edu>
 *
 * SCSI target emulation code is based on Ardis's iSCSI implementation.
 *   http://www.ardistech.com/iscsi/
 *   Copyright (C) 2002-2003 Ardis Technolgies <roman@ardistech.com>,
 *   licensed under the terms of the GNU GPL v2.0,
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

#define BLK_SHIFT	9

int sense_data_build(uint8_t *data, uint8_t res_code, uint8_t key,
		     uint8_t ascode, uint8_t ascodeq)
{
	int len = 6;

	data[0] = res_code | 1U << 7;
	data[2] = key;
	data[7] = len;
	data[12] = ascode;
	data[13] = ascodeq;

	return len + 8;
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

static int sbc_test_unit(int host_no, struct scsi_cmd *cmd, void *key)
{
	int ret = SAM_STAT_GOOD;
	uint8_t *data;

	/* how should we test a backing-storage file? */

	if (cmd->dev) {
		if (device_reserved(cmd->cmd_nexus_id, cmd->dev->lun, host_no))
			ret = SAM_STAT_RESERVATION_CONFLICT;
	} else {
		data = valloc(pagesize);
		cmd->len = sense_data_build(data, 0x70, ILLEGAL_REQUEST, 0x24, 0);
		cmd->uaddr = (unsigned long)data;
		ret = SAM_STAT_CHECK_CONDITION;
	}
	return ret;
}

static int sbc_request_sense(int host_no, struct scsi_cmd *cmd, void *key)
{
	uint8_t *data;

	data = valloc(pagesize);
	if (!data)
		return SAM_STAT_CHECK_CONDITION;

	cmd->len = sense_data_build(data, 0x70, NO_SENSE, 0, 0);
	cmd->uaddr = (unsigned long)data;
	return SAM_STAT_GOOD;
}

static int __report_luns(struct list_head *dev_list, uint8_t *lun_buf,
			 uint8_t *scb, uint8_t *p, int *len)
{
	struct tgt_device *dev;
	uint64_t lun, *data = (uint64_t *) p;
	int idx, alen, oalen, nr_luns, rbuflen = 4096, overflow;
	int result = SAM_STAT_GOOD;

	alen = __be32_to_cpu(*(uint32_t *)&scb[6]);
	if (alen < 16) {
		*len = sense_data_build(p, 0x70, ILLEGAL_REQUEST,
					0x24, 0);
		return SAM_STAT_CHECK_CONDITION;
	}

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

	*((uint32_t *) data) = __cpu_to_be32(nr_luns * 8);
	*len = min(oalen, nr_luns * 8 + 8);

	return result;
}

static int spc_report_luns(int host_no, struct scsi_cmd *cmd, void *key)
{
	struct target *target = cmd->c_target;
	struct list_head *dev_list = &target->device_list;
	uint8_t *data;

	data = valloc(pagesize);
	memset(data, 0, pagesize);
	cmd->uaddr = (unsigned long)data;

	typeof(__report_luns) *fn;
	fn = tgt_drivers[target->lid]->scsi_report_luns ? : __report_luns;
	return fn(dev_list, cmd->lun, cmd->scb, data, &cmd->len);
}

static uint64_t sbc_rw_offset(uint8_t *scb)
{
	uint64_t off;

	switch (scb[0]) {
	case READ_6:
	case WRITE_6:
		off = ((scb[1] & 0x1f) << 16) + (scb[2] << 8) + scb[3];
		break;
	case READ_10:
	case WRITE_10:
	case WRITE_VERIFY:
		off = __be32_to_cpu(*(uint32_t *) &scb[2]);
		break;
	case READ_16:
	case WRITE_16:
		off = __be64_to_cpu(*(uint64_t *) &scb[2]);
		break;
	default:
		off = 0;
		break;
	}

	return off << BLK_SHIFT;
}

static int sbc_rw(int host_no, struct scsi_cmd *cmd, void *key)
{
	int ret;
	unsigned long uaddr;
	uint8_t *data;
	bkio_submit_t *submit = cmd->c_target->bdt->bd_cmd_submit;

	if (cmd->dev) {
		if (device_reserved(cmd->cmd_nexus_id, cmd->dev->lun, host_no)) {
			ret = SAM_STAT_RESERVATION_CONFLICT;
			goto sense;
		}
	} else {
		ret = SAM_STAT_CHECK_CONDITION;
		goto sense;
	}

	switch (cmd->scb[0]) {
	case WRITE_6:
	case WRITE_10:
	case WRITE_16:
	case WRITE_VERIFY:
		cmd->rw = WRITE;
		break;
	default:
		break;
	}

	cmd->offset = sbc_rw_offset(cmd->scb);
	uaddr = cmd->uaddr;
	ret = submit(cmd->dev, cmd->scb, cmd->rw, cmd->len, &uaddr,
		     cmd->offset, &cmd->async, key);
	if (ret == SAM_STAT_GOOD) {
		cmd->mmapped = 1;
		cmd->uaddr = uaddr;
		return SAM_STAT_GOOD;
	}

sense:
	cmd->rw = READ;
	cmd->offset = 0;
	data = valloc(pagesize);
	if (data) {
		cmd->len = sense_data_build(data, 0x70, ILLEGAL_REQUEST, 0x25, 0);
		cmd->uaddr = (unsigned long) data;
	}
	return ret;
}

#define VENDOR_ID	"IET"
#define PRODUCT_ID	"VIRTUAL-DISK"
#define PRODUCT_REV	"0"

static int __sbc_inquiry(int host_no, struct scsi_cmd *cmd, void *key)
{
	int len, ret = SAM_STAT_CHECK_CONDITION;
	uint8_t *data;
	uint8_t *scb = cmd->scb;

	data = valloc(pagesize);
	memset(data, 0, pagesize);
	cmd->uaddr = (unsigned long) data;

	if (((scb[1] & 0x3) == 0x3) || (!(scb[1] & 0x3) && scb[2]))
		goto err;

	dprintf("%x %x\n", scb[1], scb[2]);

	if (!(scb[1] & 0x3)) {
		data[2] = 4;
		data[3] = 0x42;
		data[4] = 59;
		data[7] = 0x02;
		memset(data + 8, 0x20, 28);
		memcpy(data + 8,
		       VENDOR_ID, min_t(size_t, strlen(VENDOR_ID), 8));
		memcpy(data + 16,
		       PRODUCT_ID, min_t(size_t, strlen(PRODUCT_ID), 16));
		memcpy(data + 32,
		       PRODUCT_REV, min_t(size_t, strlen(PRODUCT_REV), 4));
		data[58] = 0x03;
		data[59] = 0x20;
		data[60] = 0x09;
		data[61] = 0x60;
		data[62] = 0x03;
		data[63] = 0x00;
		len = 64;
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
		goto err;

	len = min_t(int, len, scb[4]);

	if (!cmd->dev)
		data[0] = TYPE_NO_LUN;

	cmd->len = len;

	return SAM_STAT_GOOD;

err:
	cmd->len = sense_data_build(data, 0x70, ILLEGAL_REQUEST, 0x24, 0);
	return SAM_STAT_CHECK_CONDITION;
}

static int sbc_inquiry(int host_no, struct scsi_cmd *cmd, void *key)
{
	int ret, lid = cmd->c_target->lid;

	if (tgt_drivers[lid]->scsi_inquiry) {
		uint8_t *data;

		data = valloc(pagesize);
		memset(data, 0, pagesize);
		cmd->uaddr = (unsigned long)data;
		ret = tgt_drivers[lid]->scsi_inquiry(cmd->dev, host_no, cmd->lun,
						     cmd->scb, data, &cmd->len);
	} else
		ret = __sbc_inquiry(host_no, cmd, key);

	return ret;
}

static int sbc_reserve(int host_no, struct scsi_cmd *cmd, void *key)
{
	int ret;
	uint8_t *data;

	if (cmd->dev) {
		ret = device_reserve(cmd->cmd_nexus_id, cmd->dev->lun, host_no);
		if (ret)
			ret = SAM_STAT_RESERVATION_CONFLICT;
		else
			ret = SAM_STAT_GOOD;
	} else {
		data = valloc(pagesize);
		if (data) {
			cmd->uaddr = (unsigned long)data;
			cmd->len = sense_data_build(data, 0x70, ILLEGAL_REQUEST, 0x25, 0);
		}
		ret = SAM_STAT_CHECK_CONDITION;
	}
	return ret;
}

static int sbc_release(int host_no, struct scsi_cmd *cmd, void *key)
{
	int ret = SAM_STAT_CHECK_CONDITION;
	uint8_t *data;

	if (cmd->dev) {
		ret = device_release(cmd->cmd_nexus_id, cmd->dev->lun, host_no, 0);
		if (ret)
			ret = SAM_STAT_RESERVATION_CONFLICT;
		else
			ret = SAM_STAT_GOOD;
	} else {
		data = valloc(pagesize);
		if (data) {
			cmd->uaddr = (unsigned long) data;
			cmd->len = sense_data_build(data, 0x70, ILLEGAL_REQUEST, 0x25, 0);
		}
	}
	return ret;
}

static int sbc_read_capacity(int host_no, struct scsi_cmd *cmd, void *key)
{
	uint32_t *data;
	uint64_t size;
	uint8_t *scb = cmd->scb;

	data = valloc(pagesize);
	cmd->uaddr = (unsigned long) data;

	if (cmd->dev) {
		if (device_reserved(cmd->cmd_nexus_id, cmd->dev->lun, host_no))
			return SAM_STAT_RESERVATION_CONFLICT;
	} else {
		cmd->len = sense_data_build((uint8_t *)data, 0x70,
					    ILLEGAL_REQUEST, 0x25, 0);
		return SAM_STAT_CHECK_CONDITION;
	}

	if (!(scb[8] & 0x1) & (scb[2] | scb[3] | scb[4] | scb[5])) {
		cmd->len = sense_data_build((uint8_t *)data, 0x70,
					    ILLEGAL_REQUEST, 0x24, 0);
		return SAM_STAT_CHECK_CONDITION;
	}

	size = cmd->dev->size >> BLK_SHIFT;

	data[0] = (size >> 32) ?
		__cpu_to_be32(0xffffffff) : __cpu_to_be32(size - 1);
	data[1] = __cpu_to_be32(1U << BLK_SHIFT);
	cmd->len = 8;

	return SAM_STAT_GOOD;
}

static int sbc_sync_cache(int host_no, struct scsi_cmd *cmd, void *key)
{
	int ret, len;
	uint8_t *data, ascode;

	if (cmd->dev) {
		if (device_reserved(cmd->cmd_nexus_id, cmd->dev->lun, host_no))
			return SAM_STAT_RESERVATION_CONFLICT;
	} else {
		ascode = 0x25;
		goto sense;
	}

	ret = fsync(cmd->dev->fd);

	switch (ret) {
	case EROFS:
	case EINVAL:
	case EBADF:
	case EIO:
		/*
		 * is this the right sense code?
		 * what should I put for the asc/ascq?
		 */
		ascode = 0;
		goto sense;
	default:
		len = 0;
		return SAM_STAT_GOOD;
	}

sense:
	data = valloc(pagesize);
	cmd->uaddr = (unsigned long) data;
	cmd->len = sense_data_build(data, 0x70, ILLEGAL_REQUEST, ascode, 0);

	return SAM_STAT_CHECK_CONDITION;
}

static int insert_disconnect_pg(uint8_t *ptr)
{
	unsigned char disconnect_pg[] = {0x02, 0x0e, 0x80, 0x80, 0x00, 0x0a, 0x00, 0x00,
                                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

	memcpy(ptr, disconnect_pg, sizeof(disconnect_pg));
	return sizeof(disconnect_pg);
}

static int insert_caching_pg(uint8_t *ptr)
{
	unsigned char caching_pg[] = {0x08, 0x12, 0x14, 0x00, 0xff, 0xff, 0x00, 0x00,
				      0xff, 0xff, 0xff, 0xff, 0x80, 0x14, 0x00, 0x00,
				      0x00, 0x00, 0x00, 0x00};

	memcpy(ptr, caching_pg, sizeof(caching_pg));
	return sizeof(caching_pg);
}

static int insert_ctrl_m_pg(uint8_t *ptr)
{
	unsigned char ctrl_m_pg[] = {0x0a, 0x0a, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
				     0x00, 0x00, 0x02, 0x4b};

	memcpy(ptr, ctrl_m_pg, sizeof(ctrl_m_pg));
	return sizeof(ctrl_m_pg);
}

static int insert_iec_m_pg(uint8_t *ptr)
{
	unsigned char iec_m_pg[] = {0x1c, 0xa, 0x08, 0x00, 0x00, 0x00, 0x00,
				    0x00, 0x00, 0x00, 0x00, 0x00};

	memcpy(ptr, iec_m_pg, sizeof(iec_m_pg));
	return sizeof(iec_m_pg);
}

static int insert_format_m_pg(uint8_t *ptr)
{
	unsigned char format_m_pg[] = {0x03, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				       0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00,
				       0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00};
	memcpy(ptr, format_m_pg, sizeof(format_m_pg));
	return sizeof(format_m_pg);
}

static int insert_geo_m_pg(uint8_t *ptr, uint64_t sec)
{
	unsigned char geo_m_pg[] = {0x04, 0x16, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00,
				    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				    0x00, 0x00, 0x00, 0x00, 0x3a, 0x98, 0x00, 0x00};
	uint32_t ncyl, *p;

	/* assume 0xff heads, 15krpm. */
	memcpy(ptr, geo_m_pg, sizeof(geo_m_pg));
	ncyl = sec >> 14; /* 256 * 64 */
	p = (uint32_t *)(ptr + 1);
	*p = *p | __cpu_to_be32(ncyl);
	return sizeof(geo_m_pg);
}

static int sbc_mode_sense(int host_no, struct scsi_cmd *cmd, void *key)
{
	int ret = SAM_STAT_GOOD, len;
	uint8_t pcode = cmd->scb[2] & 0x3f;
	uint64_t size;
	uint8_t *data = NULL;

	data = valloc(pagesize);
	memset(data, 0, pagesize);
	cmd->uaddr = (unsigned long) data;

	if (cmd->dev) {
		if (device_reserved(cmd->cmd_nexus_id, cmd->dev->lun, host_no))
			return SAM_STAT_RESERVATION_CONFLICT;
	} else {
		cmd->len = sense_data_build((uint8_t *)data, 0x70,
					    ILLEGAL_REQUEST, 0x25, 0);
		return SAM_STAT_CHECK_CONDITION;
	}

	len = 4;
	size = cmd->dev->size >> BLK_SHIFT;

	if ((cmd->scb[1] & 0x8))
		data[3] = 0;
	else {
		data[3] = 8;
		len += 8;
		*(uint32_t *)(data + 4) = (size >> 32) ?
			__cpu_to_be32(0xffffffff) : __cpu_to_be32(size);
		*(uint32_t *)(data + 8) = __cpu_to_be32(1 << BLK_SHIFT);
	}

	switch (pcode) {
	case 0x0:
		break;
	case 0x2:
		len += insert_disconnect_pg(data + len);
		break;
	case 0x3:
		len += insert_format_m_pg(data + len);
		break;
	case 0x4:
		len += insert_geo_m_pg(data + len, size);
		break;
	case 0x8:
		len += insert_caching_pg(data + len);
		break;
	case 0xa:
		len += insert_ctrl_m_pg(data + len);
		break;
	case 0x1c:
		len += insert_iec_m_pg(data + len);
		break;
	case 0x3f:
		len += insert_disconnect_pg(data + len);
		len += insert_format_m_pg(data + len);
		len += insert_geo_m_pg(data + len, size);
		len += insert_caching_pg(data + len);
		len += insert_ctrl_m_pg(data + len);
		len += insert_iec_m_pg(data + len);
		break;
	default:
		ret = SAM_STAT_CHECK_CONDITION;
		len = sense_data_build(data, 0x70, ILLEGAL_REQUEST,0x24, 0);
	}

	data[0] = len - 1;
	cmd->len = len;
	return ret;
}

static int spc_start_stop(int host_no, struct scsi_cmd *cmd, void *key)
{
	cmd->len = 0;

	if (cmd->dev) {
		if (device_reserved(cmd->cmd_nexus_id, cmd->dev->lun, host_no))
			return SAM_STAT_RESERVATION_CONFLICT;
	} else {
		uint8_t *data;

		data = valloc(pagesize);
		memset(data, 0, pagesize);
		cmd->uaddr = (unsigned long) data;

		cmd->len = sense_data_build((uint8_t *)data, 0x70,
					    ILLEGAL_REQUEST, 0x25, 0);
		return SAM_STAT_CHECK_CONDITION;
	}

	return SAM_STAT_GOOD;
}

static int spc_illegal_op(int host_no, struct scsi_cmd *cmd, void *key)
{
	uint8_t *data;

	data = valloc(pagesize);
	memset(data, 0, pagesize);
	cmd->uaddr = (unsigned long) data;
	cmd->len = sense_data_build(data, 0x70, ILLEGAL_REQUEST,0x24, 0);

	return SAM_STAT_CHECK_CONDITION;
}

struct device_command_operations sbc_ops[] = {
	{sbc_test_unit,},
	{spc_illegal_op,},
	{spc_illegal_op,},
	{sbc_request_sense,},
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
	{sbc_inquiry,},
	{spc_illegal_op,},
	{spc_illegal_op,},
	{spc_illegal_op,},
	{sbc_reserve,},
	{sbc_release,},

	{spc_illegal_op,},
	{spc_illegal_op,},
	{sbc_mode_sense,},
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
	{sbc_test_unit},

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

	[0x40 ... 0x7f] = {spc_illegal_op,},

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
	{sbc_test_unit},

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
	{sbc_test_unit,},

	[0xb0 ... 0xff] = {spc_illegal_op},
};

int scsi_cmd_perform(int host_no, struct scsi_cmd *cmd, void *key)
{
	unsigned char op = cmd->scb[0];

	return sbc_ops[op].cmd_perform(host_no, cmd, key);
}
