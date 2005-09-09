/*
 * SCSI command processing
 *
 * (C) 2004 - 2005 FUJITA Tomonori <tomof@acm.org>
 * (C) 2005 Mike Christie <michaelc@cs.wisc.edu>
 * This code is licenced under the GPL.
 *
 * SCSI target emulation code is based on Ardis's iSCSI implementation.
 *   http://www.ardistech.com/iscsi/
 *   Copyright (C) 2002-2003 Ardis Technolgies <roman@ardistech.com>,
 *   licensed under the terms of the GNU GPL v2.0,
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <dirent.h>
#include <unistd.h>
#include <errno.h>
#include <scsi/scsi.h>
#include <asm/byteorder.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "stgtd.h"

#define cpu_to_be32 __cpu_to_be32
#define be32_to_cpu __be32_to_cpu
#define cpu_to_be64 __cpu_to_be64

#ifndef REPORT_LUNS
#define REPORT_LUNS           0xa0
#endif

#ifndef SERVICE_ACTION_IN
#define SERVICE_ACTION_IN     0x9e
#endif

#define SAM_STAT_GOOD            0x00
#define SAM_STAT_CHECK_CONDITION 0x02

static uint32_t blk_shift = 9;

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

static int device_info(int tid, uint64_t lun, uint64_t *size)
{
	int fd, err;
	char path[PATH_MAX], buf[128];

	sprintf(path, "/sys/class/stgt_device/device%d:%" PRIu64 "/size",
		tid, lun);

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return fd;
	err = read(fd, buf, sizeof(buf));
	if (err < 0)
		return err;
	*size = strtoull(buf, NULL, 10);

	close(fd);
	return 0;
}

static int sense_data_build(uint8_t *data, uint8_t res_code, uint8_t key,
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
	*p = *p | cpu_to_be32(ncyl);
	return sizeof(geo_m_pg);
}

static int mode_sense(int tid, uint64_t lun, uint8_t *scb, uint8_t *data, int *len)
{
	int result = SAM_STAT_GOOD;
	uint8_t pcode = scb[2] & 0x3f;
	uint64_t size;

	if (device_info(tid, lun, &size) < 0) {
		*len = sense_data_build(data, 0x70, ILLEGAL_REQUEST,
					0x25, 0);
		return SAM_STAT_CHECK_CONDITION;
	}

	*len = 4;
	size >>= blk_shift;

	if ((scb[1] & 0x8))
		data[3] = 0;
	else {
		data[3] = 8;
		*len += 8;
		*(uint32_t *)(data + 4) = (size >> 32) ?
			cpu_to_be32(0xffffffff) : cpu_to_be32(size);
		*(uint32_t *)(data + 8) = cpu_to_be32(1 << blk_shift);
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

static int inquiry(int tid, uint64_t lun, uint8_t *scb, uint8_t *data, int *len)
{
	int result = SAM_STAT_CHECK_CONDITION;

	if (((scb[1] & 0x3) == 0x3) || (!(scb[1] & 0x3) && scb[2]))
		goto err;

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
#define SCSI_ID_LEN	24
			uint32_t tmp = SCSI_ID_LEN * sizeof(uint8_t);

			data[1] = 0x83;
			data[3] = tmp + 4;
			data[4] = 0x1;
			data[5] = 0x1;
			data[7] = tmp;
			if (lun != ~0ULL)
				sprintf(data + 8, "deadbeaf%d:%" PRIu64, tid, lun);
			*len = tmp + 8;
			result = SAM_STAT_GOOD;
		}
	}

	if (result != SAM_STAT_GOOD)
		goto err;

	*len = min_t(int, *len, scb[4]);

	if (lun == ~0ULL)
		data[0] = TYPE_NO_LUN;

	return SAM_STAT_GOOD;

err:
	*len = sense_data_build(data, 0x70, ILLEGAL_REQUEST,
				0x24, 0);
	return SAM_STAT_CHECK_CONDITION;
}

static int report_luns(int tid, uint32_t unused, uint8_t *scb, uint8_t *p, int *len)
{
	/*
	 * TODO Convert to 64 bits
	 */
	uint32_t lun;
	uint32_t *data = (uint32_t *) p;
	int idx, alen, oalen, rbuflen, nr_luns;
	DIR *dir;
	struct dirent *ent;
	char buf[128];
	int result = SAM_STAT_GOOD;

	dir = opendir("/sys/class/stgt_device");
	if (!dir) {
		perror("can't open /sys/class/stgt_device\n");
		exit(0);
	}

	alen = be32_to_cpu(*(uint32_t *)&scb[6]);
	if (alen < 16) {
		*len = sense_data_build(p, 0x70, ILLEGAL_REQUEST,
					0x24, 0);
		result = SAM_STAT_CHECK_CONDITION;
		goto out;
	}

	alen &= ~(8 - 1);
	oalen = alen;

	/* We'll set data[0] later. */
	data[1] = 0;

	alen -= 8;
	rbuflen = 8192 - 8; /* FIXME */
	idx = 2;
	nr_luns = 0;

	sprintf(buf, "device%d:", tid);
	while ((ent = readdir(dir))) {
		if (!strncmp(ent->d_name, buf, strlen(buf))) {
			sscanf(ent->d_name, "device%d:%u", &tid, &lun);
			data[idx++] = cpu_to_be32((0x3ff & lun) << 16 |
						  ((lun > 0xff) ? (0x1 << 30) : 0));
			data[idx++] = 0;
			if (!(alen -= 8))
				break;
			if (!(rbuflen -= 8)) {
				fprintf(stderr, "FIXME: too many luns\n");
				exit(-1);
			}
			nr_luns++;
		}
	}

	data[0] = cpu_to_be32(nr_luns * 8);
	*len = min(oalen, nr_luns * 8 + 8);
out:
	closedir(dir);
	return result;
}

static int read_capacity(int tid, uint64_t lun, uint8_t *scb, uint8_t *p, int *len)
{
	uint32_t *data = (uint32_t *) p;
	uint64_t size;

	if (!(scb[8] & 0x1) & (scb[2] | scb[3] | scb[4] | scb[5])) {
		*len = sense_data_build(p, 0x70, ILLEGAL_REQUEST,
					0x24, 0);
		return SAM_STAT_CHECK_CONDITION;
	}

	if (device_info(tid, lun, &size) < 0) {
		*len = sense_data_build(p, 0x70, ILLEGAL_REQUEST,
					0x25, 0);
		return SAM_STAT_CHECK_CONDITION;
	}

	size >>= blk_shift;

	data[0] = (size >> 32) ?
		cpu_to_be32(0xffffffff) : cpu_to_be32(size - 1);
	data[1] = cpu_to_be32(1U << blk_shift);
	*len = 8;

	return SAM_STAT_GOOD;
}

static int sync_cache(int tid, uint64_t lun, uint8_t *scb, uint8_t *data,
		      int *len)
{
	int fd, err;
	char path[PATH_MAX], buf[PATH_MAX];

	sprintf(path, "/sys/class/stgt_device/device%d:%" PRIu64 "/path", tid, lun);

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		perror("scsi sync_cache could not get LU's path");
		err = EINVAL;
		goto einval;
	}

	err = read(fd, buf, sizeof(buf));
	close(fd);
	if (err < 0) {
		perror("scsi sync_cache could not read LUN path");
		err = EIO;
		goto eio;
	}
	/*
	 * yuck! wtf should I be using
	 */
	memset(path, 0, PATH_MAX);
	sscanf(buf, "%s\n", path);

	fd = open(path, O_RDWR);
	if (fd < 0) {
		perror("scsi sync_cache could not open device");
		err = EIO;
		goto eio;
	}
	err = fsync(fd);
	close(fd);

	switch (err) {
	case EROFS:
	case EINVAL:
	case EBADF:
einval:
		/* is this the right sense code? */
		*len = sense_data_build(data, 0x70, ILLEGAL_REQUEST, 0, 0);
		return SAM_STAT_CHECK_CONDITION;
	case EIO:
eio:
		/* what should I put for the asc/ascq? */
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
static int request_sense(int tid, uint64_t lun, uint8_t *scb, uint8_t *data, int* len)
{
	*len = sense_data_build(data, 0x70, NO_SENSE, 0, 0);

	return SAM_STAT_GOOD;
}

static int sevice_action(int tid, uint64_t lun, uint8_t *scb, uint8_t *p, int *len)
{
	uint32_t *data = (uint32_t *) p;
	uint64_t *data64, size;

	if (device_info(tid, lun, &size) < 0) {
		*len = sense_data_build(p, 0x70, ILLEGAL_REQUEST,
					0x25, 0);
		return SAM_STAT_CHECK_CONDITION;
	}
	size >>= blk_shift;

	data64 = (uint64_t *) data;
	data64[0] = cpu_to_be64(size - 1);
	data[2] = cpu_to_be32(1UL << blk_shift);

	*len = 32;

	return SAM_STAT_GOOD;
}

int scsi_cmnd_process(int tid, uint64_t lun, uint8_t *scb, uint8_t *data, int *len)
{
	int result = SAM_STAT_GOOD;

	dprintf("%x\n", scb[0]);

	if (lun == ~0ULL)
		switch (scb[0]) {
		case REQUEST_SENSE:
		case INQUIRY:
		case REPORT_LUNS:
			break;
		default:
			*len = sense_data_build(data, 0x70, ILLEGAL_REQUEST,
						0x25, 0);
			result = SAM_STAT_CHECK_CONDITION;
			goto out;
		}

	switch (scb[0]) {
	case INQUIRY:
		result = inquiry(tid, lun, scb, data, len);
		break;
	case REPORT_LUNS:
		result = report_luns(tid, lun, scb, data, len);
		break;
	case READ_CAPACITY:
		result = read_capacity(tid, lun, scb, data, len);
		break;
	case MODE_SENSE:
		result = mode_sense(tid, lun, scb, data, len);
		break;
	case REQUEST_SENSE:
		result = request_sense(tid, lun, scb, data, len);
		break;
	case SERVICE_ACTION_IN:
		result = sevice_action(tid, lun, scb, data, len);
		break;
	case SYNCHRONIZE_CACHE:
		result = sync_cache(tid, lun, scb, data, len);
		break;
	case START_STOP:
	case TEST_UNIT_READY:
	case VERIFY:
		*len = 0;
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
		dprintf("BUG? %u %" PRIu64 "\n", scb[0], lun);
		*len = 0;
		break;
	}

out:
	return result;
}
