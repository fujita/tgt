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
#include <asm/byteorder.h>
#include <linux/fs.h>

#include "list.h"
#include "util.h"
#include "tgtd.h"
#include "driver.h"

#include <scsi/scsi.h>

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

static int mode_sense(struct tgt_device *dev, uint8_t *scb, uint8_t *data, int *len)
{
	int result = SAM_STAT_GOOD;
	uint8_t pcode = scb[2] & 0x3f;
	uint64_t size;

	*len = 4;
	size = dev->size >> BLK_SHIFT;

	if ((scb[1] & 0x8))
		data[3] = 0;
	else {
		data[3] = 8;
		*len += 8;
		*(uint32_t *)(data + 4) = (size >> 32) ?
			__cpu_to_be32(0xffffffff) : __cpu_to_be32(size);
		*(uint32_t *)(data + 8) = __cpu_to_be32(1 << BLK_SHIFT);
	}

	switch (pcode) {
	case 0x0:
		break;
	case 0x2:
		*len += insert_disconnect_pg(data + *len);
		break;
	case 0x3:
		*len += insert_format_m_pg(data + *len);
		break;
	case 0x4:
		*len += insert_geo_m_pg(data + *len, size);
		break;
	case 0x8:
		*len += insert_caching_pg(data + *len);
		break;
	case 0xa:
		*len += insert_ctrl_m_pg(data + *len);
		break;
	case 0x1c:
		*len += insert_iec_m_pg(data + *len);
		break;
	case 0x3f:
		*len += insert_disconnect_pg(data + *len);
		*len += insert_format_m_pg(data + *len);
		*len += insert_geo_m_pg(data + *len, size);
		*len += insert_caching_pg(data + *len);
		*len += insert_ctrl_m_pg(data + *len);
		*len += insert_iec_m_pg(data + *len);
		break;
	default:
		result = SAM_STAT_CHECK_CONDITION;
		*len = sense_data_build(data, 0x70, ILLEGAL_REQUEST,
					0x24, 0);
	}

	data[0] = *len - 1;

	return result;
}

#define VENDOR_ID	"IET"
#define PRODUCT_ID	"VIRTUAL-DISK"
#define PRODUCT_REV	"0"

static int __inquiry(struct tgt_device *dev, int host_no, uint8_t *lun_buf,
		     uint8_t *scb, uint8_t *data, int *len)
{
	int result = SAM_STAT_CHECK_CONDITION;

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
		*len = 64;
		result = SAM_STAT_GOOD;
	} else if (scb[1] & 0x2) {
		/* CmdDt bit is set */
		/* We do not support it now. */
		data[1] = 0x1;
		data[5] = 0;
		*len = 6;
		result = SAM_STAT_GOOD;
	} else if (scb[1] & 0x1) {
		/* EVPD bit set */
		if (scb[2] == 0x0) {
			data[1] = 0x0;
			data[3] = 3;
			data[4] = 0x0;
			data[5] = 0x80;
			data[6] = 0x83;
			*len = 7;
			result = SAM_STAT_GOOD;
		} else if (scb[2] == 0x80) {
			data[1] = 0x80;
			data[3] = 4;
			memset(data + 4, 0x20, 4);
			*len = 8;
			result = SAM_STAT_GOOD;
		} else if (scb[2] == 0x83) {
			uint32_t tmp = SCSI_ID_LEN * sizeof(uint8_t);

			data[1] = 0x83;
			data[3] = tmp + 4;
			data[4] = 0x1;
			data[5] = 0x1;
			data[7] = tmp;
			if (dev)
				strncpy(data + 8, dev->scsi_id, SCSI_ID_LEN);
			*len = tmp + 8;
			result = SAM_STAT_GOOD;
		}
	}

	if (result != SAM_STAT_GOOD)
		goto err;

	*len = min_t(int, *len, scb[4]);

	if (!dev)
		data[0] = TYPE_NO_LUN;

	return SAM_STAT_GOOD;

err:
	*len = sense_data_build(data, 0x70, ILLEGAL_REQUEST,
				0x24, 0);
	return SAM_STAT_CHECK_CONDITION;
}

static int inquiry(int lid, struct tgt_device *dev, int host_no,
		   uint8_t *lun_buf, uint8_t *scb, uint8_t *data, int *len)
{
	typeof(__inquiry) *fn;

	fn = tgt_drivers[lid]->scsi_inquiry ? : __inquiry;
	return fn(dev, host_no, lun_buf, scb, data, len);
}

static int __report_luns(struct list_head *dev_list, uint8_t *lun_buf,
			 uint8_t *scb, uint8_t *p, int *len)
{
	struct tgt_device *dev;
	uint64_t lun, *data = (uint64_t *) p;
	int idx, alen, oalen, nr_luns, rbuflen = 4096;
	int result = SAM_STAT_GOOD;

	memset(data, 0, rbuflen);

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

	list_for_each_entry(dev, dev_list, d_list) {
		lun = dev->lun;

		lun = ((lun > 0xff) ? (0x1 << 30) : 0) | ((0x3ff & lun) << 16);
		data[idx++] = __cpu_to_be64(lun << 32);
		if (!(alen -= 8))
			break;
		if (!(rbuflen -= 8)) {
			fprintf(stderr, "FIXME: too many luns\n");
			exit(-1);
		}
		nr_luns++;
	}

	*((uint32_t *) data) = __cpu_to_be32(nr_luns * 8);
	*len = min(oalen, nr_luns * 8 + 8);

	return result;
}

static int report_luns(int lid, struct list_head *dev_list, uint8_t *lun_buf,
		       uint8_t *scb, uint8_t *p, int *len)
{
	typeof(__report_luns) *fn;
	fn = tgt_drivers[lid]->scsi_report_luns ? : __report_luns;
	return fn(dev_list, lun_buf, scb, p, len);
}

static int read_capacity(struct tgt_device *dev, uint8_t *scb, uint8_t *p, int *len)
{
	uint32_t *data = (uint32_t *) p;
	uint64_t size;

	if (!(scb[8] & 0x1) & (scb[2] | scb[3] | scb[4] | scb[5])) {
		*len = sense_data_build(p, 0x70, ILLEGAL_REQUEST,
					0x24, 0);
		return SAM_STAT_CHECK_CONDITION;
	}

	size = dev->size >> BLK_SHIFT;

	data[0] = (size >> 32) ?
		__cpu_to_be32(0xffffffff) : __cpu_to_be32(size - 1);
	data[1] = __cpu_to_be32(1U << BLK_SHIFT);
	*len = 8;

	return SAM_STAT_GOOD;
}

static int sync_cache(struct tgt_device *dev, uint8_t *data, int *len)
{
	int err;

	err = fsync(dev->fd);

	switch (err) {
	case EROFS:
	case EINVAL:
	case EBADF:
	case EIO:
		/*
		 * is this the right sense code?
		 * what should I put for the asc/ascq?
		 */
		*len = sense_data_build(data, 0x70, ILLEGAL_REQUEST, 0, 0);
		return SAM_STAT_CHECK_CONDITION;
	default:
		*len = 0;
		return SAM_STAT_GOOD;
	}
}

/*
 * TODO: We always assume autosense.
 */
static int request_sense(uint8_t *data, int* len)
{
	*len = sense_data_build(data, 0x70, NO_SENSE, 0, 0);

	return SAM_STAT_GOOD;
}

static int sevice_action(struct tgt_device *dev, uint8_t *scb, uint8_t *p, int *len)
{
	uint32_t *data = (uint32_t *) p;
	uint64_t *data64, size;

	size = dev->size >> BLK_SHIFT;

	data64 = (uint64_t *) data;
	data64[0] = __cpu_to_be64(size - 1);
	data[2] = __cpu_to_be32(1UL << BLK_SHIFT);

	*len = 32;

	return SAM_STAT_GOOD;
}

static uint64_t scsi_cmd_data_offset(uint8_t *scb)
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

static int scsi_cmd_rw(uint8_t *scb, uint8_t *rw)
{
	int is_alloc = 0;

	switch (scb[0]) {
	case READ_6:
	case READ_10:
	case READ_16:
		*rw = READ;
		break;
	case WRITE_6:
	case WRITE_10:
	case WRITE_16:
	case WRITE_VERIFY:
		*rw = WRITE;
		break;
	default:
		is_alloc = 1;
	}
	return is_alloc;
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

int scsi_cmd_perform(int lid, int host_no, uint8_t *pdu,
		     int *len, uint32_t datalen, unsigned long *uaddr, uint8_t *rw,
		     uint8_t *try_map, uint64_t *offset, uint8_t *lun_buf,
		     struct tgt_device *dev, struct list_head *dev_list, int *async,
		     void *key)
{
	int result = SAM_STAT_GOOD;
	uint8_t *data = NULL, *scb = pdu;

	dprintf("%x %u\n", scb[0], datalen);

	*async = *offset = 0;
	if (scsi_cmd_rw(scb, rw)) {
		data = valloc(PAGE_SIZE);
		memset(data, 0, PAGE_SIZE);
	}

	if (!dev)
		switch (scb[0]) {
		case REQUEST_SENSE:
		case INQUIRY:
		case REPORT_LUNS:
			break;
		default:
			*offset = 0;
			if (!data) {
				data = valloc(PAGE_SIZE);
				memset(data, 0, PAGE_SIZE);
			}
			*len = sense_data_build(data, 0x70, ILLEGAL_REQUEST,
						0x25, 0);
			result = SAM_STAT_CHECK_CONDITION;
			goto out;
		}

	switch (scb[0]) {
	case INQUIRY:
		result = inquiry(lid, dev, host_no, lun_buf, scb, data, len);
		break;
	case REPORT_LUNS:
		result = report_luns(lid, dev_list, lun_buf, scb, data, len);
		break;
	case READ_CAPACITY:
		result = read_capacity(dev, scb, data, len);
		break;
	case MODE_SENSE:
		result = mode_sense(dev, scb, data, len);
		break;
	case REQUEST_SENSE:
		result = request_sense(data, len);
		break;
	case SERVICE_ACTION_IN:
		result = sevice_action(dev, scb, data, len);
		break;
	case SYNCHRONIZE_CACHE:
		result = sync_cache(dev, data, len);
		break;
	case START_STOP:
	case TEST_UNIT_READY:
	case VERIFY:
		*len = 0;
		break;
	case READ_6:
	case READ_10:
	case READ_16:
	case WRITE_6:
	case WRITE_10:
	case WRITE_16:
	case WRITE_VERIFY:
		*offset = scsi_cmd_data_offset(scb);
		result = tgt_drivers[lid]->bdt->bd_cmd_submit(dev, *rw, datalen,
							      uaddr, *offset, async, key);
		if (result == SAM_STAT_GOOD) {
			*len = datalen;
			*try_map = 1;
		} else {
			*rw = READ;
			*offset = 0;
			if (!data)
				data = valloc(PAGE_SIZE);
			*len = sense_data_build(data, 0x70, ILLEGAL_REQUEST,
						0x25, 0);
		}
		break;
	case RESERVE:
	case RELEASE:
	case RESERVE_10:
	case RELEASE_10:
	default:
		eprintf("unknown command %x %u\n", scb[0], datalen);
		*len = 0;
		break;
	}

out:
	if (data)
		*uaddr = (unsigned long) data;

	return result;
}
