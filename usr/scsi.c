/*
 * (C) 2004 - 2005 FUJITA Tomonori <tomof@acm.org>
 * This code is licenced under the GPL.
 *
 * heavily based on code from kernel/iscsi.c:
 *   Copyright (C) 2002-2003 Ardis Technolgies <roman@ardistech.com>,
 *   licensed under the terms of the GNU GPL v2.0,
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <scsi/scsi.h>
#include <asm/byteorder.h>

#define cpu_to_be32 __cpu_to_be32
#define be32_to_cpu __be32_to_cpu
#define cpu_to_be64 __cpu_to_be64

#ifndef REPORT_LUNS
#define REPORT_LUNS           0xa0
#endif

#ifndef SERVICE_ACTION_IN
#define SERVICE_ACTION_IN     0x9e
#endif

static uint32_t blk_shift = 9;
static uint64_t blk_cnt = 1 << 20;

#define eprintf(fmt, args...)						\
do {									\
	fprintf(stderr, "%s(%d) " fmt, __FUNCTION__, __LINE__, args);	\
} while (0)

#define min(x,y) ({ \
	typeof(x) _x = (x);	\
	typeof(y) _y = (y);	\
	(void) (&_x == &_y);		\
	_x < _y ? _x : _y; })

#define max(x,y) ({ \
	typeof(x) _x = (x);	\
	typeof(y) _y = (y);	\
	(void) (&_x == &_y);		\
	_x > _y ? _x : _y; })

#define min_t(type,x,y) \
	({ type __x = (x); type __y = (y); __x < __y ? __x: __y; })
#define max_t(type,x,y) \
	({ type __x = (x); type __y = (y); __x > __y ? __x: __y; })

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
	*p = *p | cpu_to_be32(ncyl);
	return sizeof(geo_m_pg);
}

static int build_mode_sense_response(uint8_t *scb, uint8_t *data)
{
	int len = 4, err = 0;
	uint8_t pcode = scb[2] & 0x3f;

	if ((scb[1] & 0x8))
		data[3] = 0;
	else {
		data[3] = 8;
		len += 8;
		*(uint32_t *)(data + 4) = (blk_cnt >> 32) ?
			cpu_to_be32(0xffffffff) : cpu_to_be32(blk_cnt);
		*(uint32_t *)(data + 8) = cpu_to_be32(1 << blk_shift);
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
		len += insert_geo_m_pg(data + len, blk_cnt);
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
		len += insert_geo_m_pg(data + len, blk_cnt);
		len += insert_caching_pg(data + len);
		len += insert_ctrl_m_pg(data + len);
		len += insert_iec_m_pg(data + len);
		break;
	default:
		err = -1;
	}

	data[0] = len - 1;

	return len;
}

#define VENDOR_ID	"IET"
#define PRODUCT_ID	"VIRTUAL-DISK"
#define PRODUCT_REV	"0"

static int build_inquiry_response(uint8_t *scb, uint8_t *data)
{
	int err = -1;
	int len = 0;

	if (((scb[1] & 0x3) == 0x3) || (!(scb[1] & 0x3) && scb[2]))
		return err;

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
		err = 0;
	} else if (scb[1] & 0x2) {
		/* CmdDt bit is set */
		/* We do not support it now. */
		data[1] = 0x1;
		data[5] = 0;
		len = 6;
		err = 0;
	} else if (scb[1] & 0x1) {
		/* EVPD bit set */
		if (scb[2] == 0x0) {
			data[1] = 0x0;
			data[3] = 3;
			data[4] = 0x0;
			data[5] = 0x80;
			data[6] = 0x83;
			len = 7;
			err = 0;
		} else if (scb[2] == 0x80) {
			data[1] = 0x80;
			data[3] = 4;
			memset(data + 4, 0x20, 4);
			len = 8;
			err = 0;
		} else if (scb[2] == 0x83) {
#define SCSI_ID_LEN	24
			uint32_t tmp = SCSI_ID_LEN * sizeof(uint8_t);

			data[1] = 0x83;
			data[3] = tmp + 4;
			data[4] = 0x1;
			data[5] = 0x1;
			data[7] = tmp;
			memcpy(data + 8, "deadbeaf", tmp);
			len = tmp + 8;
			err = 0;
		}
	}

	len = min_t(int, len, scb[4]);

/* 	if (!cmnd->lun) */
/* 		data[0] = TYPE_NO_LUN; */

	return len;
}

static int build_report_luns_response(uint8_t *scb, uint8_t *p)
{
	uint32_t size, len, lun = 0;
	uint32_t *data = (uint32_t *) p;

	size = be32_to_cpu(*(uint32_t *)&scb[6]);
	if (size < 16)
		return -1;

	len = 8;
	size = min(size & ~(8 - 1), len + 8);

	*data++ = cpu_to_be32(len);
	*data++ = 0;

	*data++ = cpu_to_be32((0x3ff & lun) << 16 |
			      (lun > 0xff) ? (0x1 << 30) : 0);
	*data++ = 0;

	return size;
}

static int build_read_capacity_response(uint8_t *scb, uint8_t *p)
{
	int len;
	uint32_t *data = (uint32_t *) p;

	data[0] = (blk_cnt >> 32) ?
		cpu_to_be32(0xffffffff) : cpu_to_be32(blk_cnt - 1);
	data[1] = cpu_to_be32(1U << blk_shift);

	len = 8;

	return len;
}

static int build_request_sense_response(uint8_t *scb, uint8_t *data)
{
	int len;

	data[0] = 0xf0;
	data[1] = 0;
	data[2] = NO_SENSE;
	data[7] = 10;

	len = 18;

	return len;
}

static int build_sevice_action_response(uint8_t *scb, uint8_t *p)
{
	int len;
	uint32_t *data = (uint32_t *) p;
	uint64_t *data64;

	data64 = (uint64_t *) data;
	data64[0] = cpu_to_be64(blk_cnt - 1);
	data[2] = cpu_to_be32(1UL << blk_shift);

	len = 32;

	return len;
}

int disk_execute_cmnd(uint8_t *scb, uint8_t *data)
{
	int len = -1;

	eprintf("%x\n", scb[0]);

	switch (scb[0]) {
	case INQUIRY:
		len = build_inquiry_response(scb, data);
		break;
	case REPORT_LUNS:
		len = build_report_luns_response(scb, data);
		break;
	case READ_CAPACITY:
		len = build_read_capacity_response(scb, data);
		break;
	case MODE_SENSE:
		len = build_mode_sense_response(scb, data);
		break;
	case REQUEST_SENSE:
		len = build_request_sense_response(scb, data);
		break;
	case SERVICE_ACTION_IN:
		len = build_sevice_action_response(scb, data);
		break;
	case START_STOP:
	case TEST_UNIT_READY:
	case SYNCHRONIZE_CACHE:
	case VERIFY:
		len = 0;
		break;
	case READ_6:
	case READ_10:
	case WRITE_6:
	case WRITE_10:
	case WRITE_VERIFY:
	case RESERVE:
	case RELEASE:
	case RESERVE_10:
	case RELEASE_10:
	default:
		eprintf("kernel module bug %d\n", scb[0]);
		exit(-1);
		break;
	}

	return len;
}
