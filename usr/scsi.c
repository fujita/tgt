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
#include <scsi/scsi.h>
#include <scsi/scsi_tgt_if.h>
#include <sys/mman.h>

#include "tgtd.h"

#define cpu_to_be32 __cpu_to_be32
#define be32_to_cpu __be32_to_cpu
#define cpu_to_be64 __cpu_to_be64
#define be64_to_cpu __be64_to_cpu

#define BLK_SHIFT	9

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

#define GETTARGET(x) ((int)((((uint64_t)(x)) >> 56) & 0x003f))
#define GETBUS(x) ((int)((((uint64_t)(x)) >> 53) & 0x0007))
#define GETLUN(x) ((int)((((uint64_t)(x)) >> 48) & 0x001f))

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
			cpu_to_be32(0xffffffff) : cpu_to_be32(size);
		*(uint32_t *)(data + 8) = cpu_to_be32(1 << BLK_SHIFT);
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

struct inquiry_data {
	uint8_t qual_type;
	uint8_t rmb_reserve;
	uint8_t version;
	uint8_t aerc_naca_hisup_format;
	uint8_t addl_len;
	uint8_t sccs_reserved;
	uint8_t bque_encserv_vs_multip_mchngr_reserved;
	uint8_t reladr_reserved_linked_cmdqueue_vs;
	char vendor[8];
	char product[16];
	char revision[4];
	char vendor_specific[20];
	char reserved1[2];
	char version_descriptor[16];
	char reserved2[22];
	char unique[158];
};

#define	IBMVSTGT_HOSTDIR	"/sys/class/scsi_host/host"

static int ibmvstgt_inquiry(int host_no, uint64_t lun, uint8_t *data)
{
	struct inquiry_data *id = (struct inquiry_data *) data;
	char system_id[256], path[256], buf[32];
	int fd, err, partition_number;
	unsigned int unit_address;

	snprintf(path, sizeof(path), IBMVSTGT_HOSTDIR "%d/system_id", host_no);
	fd = open(path, O_RDONLY);
	memset(system_id, 0, sizeof(system_id));
	err = read(fd, system_id, sizeof(system_id));
	close(fd);

	snprintf(path, sizeof(path), IBMVSTGT_HOSTDIR "%d/partition_number",
		 host_no);
	fd = open(path, O_RDONLY);
	err = read(fd, buf, sizeof(buf));
	partition_number = strtoul(buf, NULL, 10);
	close(fd);

	snprintf(path, sizeof(path), IBMVSTGT_HOSTDIR "%d/unit_address",
		 host_no);
	fd = open(path, O_RDONLY);
	err = read(fd, buf, sizeof(buf));
	unit_address = strtoul(buf, NULL, 0);
	close(fd);

	dprintf("%d %s %d %x %" PRIx64 "\n",
		host_no, system_id, partition_number, unit_address, lun);

	id->qual_type = TYPE_DISK;
	id->rmb_reserve = 0x00;
	id->version = 0x84;	/* ISO/IE		  */
	id->aerc_naca_hisup_format = 0x22;/* naca & fmt 0x02 */
	id->addl_len = sizeof(*id) - 4;
	id->bque_encserv_vs_multip_mchngr_reserved = 0x00;
	id->reladr_reserved_linked_cmdqueue_vs = 0x02;/*CMDQ*/
	memcpy(id->vendor, "IBM	    ", 8);
	/* Don't even ask about the next bit.  AIX uses
	 * hardcoded device naming to recognize device types
	 * and their client won't  work unless we use VOPTA and
	 * VDASD.
	 */
	memcpy(id->product, "VDASD blkdev    ", 16);
	memcpy(id->revision, "0001", 4);
	snprintf(id->unique,sizeof(id->unique),
		 "IBM-VSCSI-%s-P%d-%x-%d-%d-%d\n",
		 system_id,
		 partition_number,
		 unit_address,
		 GETBUS(lun),
		 GETTARGET(lun),
		 GETLUN(lun));

	return sizeof(*id);
}

static int inquiry(struct tgt_device *dev, int host_no, uint8_t *lun_buf,
		   uint8_t *scb, uint8_t *data, int *len)
{
	uint64_t lun;
	int result = SAM_STAT_CHECK_CONDITION;

	lun = scsi_get_devid(lun_buf);

	if (((scb[1] & 0x3) == 0x3) || (!(scb[1] & 0x3) && scb[2]))
		goto err;

	dprintf("%" PRIx64 " %x %x\n", lun, scb[1], scb[2]);

	if (!(scb[1] & 0x3)) {
		*len = ibmvstgt_inquiry(host_no, *((uint64_t *) lun_buf), data);
#if 0
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
#endif
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

	if (!dev) {
		dprintf("%" PRIu64 "\n", lun);
		data[0] = TYPE_NO_LUN;
	}

	return SAM_STAT_GOOD;

err:
	*len = sense_data_build(data, 0x70, ILLEGAL_REQUEST,
				0x24, 0);
	return SAM_STAT_CHECK_CONDITION;
}

uint64_t make_lun(unsigned int bus, unsigned int target, unsigned int lun)
{
	uint16_t result = (0x8000 |
			   ((target & 0x003f) << 8) |
			   ((bus & 0x0007) << 5) |
			   (lun & 0x001f));
	return ((uint64_t) result) << 48;
}

static int report_luns(struct list_head *dev_list, uint8_t *lun_buf, uint8_t *scb,
		       uint8_t *p, int *len)
{
	struct tgt_device *dev;
	uint64_t lun, *data = (uint64_t *) p;
	int idx, alen, oalen, nr_luns, rbuflen = 4096;
	int result = SAM_STAT_GOOD;

	memset(data, 0, rbuflen);

	alen = be32_to_cpu(*(uint32_t *)&scb[6]);
	if (alen < 16) {
		*len = sense_data_build(p, 0x70, ILLEGAL_REQUEST,
					0x24, 0);
		return SAM_STAT_CHECK_CONDITION;
	}

	alen &= ~(8 - 1);
	oalen = alen;

	if ((*((uint64_t *) lun_buf))) {
		dprintf("Another sick hack for ibmvstgt\n");
		nr_luns = 1;
		goto done;
	}

	alen -= 8;
	rbuflen -= 8; /* FIXME */
	idx = 1;
	nr_luns = 0;

	/* ibmvstgt hack */
	idx = 2;
	nr_luns = 1;

	list_for_each_entry(dev, dev_list, dlist) {
		lun = dev->lun;

		/* ibmvstgt hack */
/* 		lun = ((lun > 0xff) ? (0x1 << 30) : 0) | ((0x3ff & lun) << 16); */
		lun = make_lun(0, lun & 0x003f, 0);
		dprintf("%" PRIx64 "\n", lun);
/* 		data[idx++] = cpu_to_be64(lun << 32); */
		data[idx++] = cpu_to_be64(lun);
		if (!(alen -= 8))
			break;
		if (!(rbuflen -= 8)) {
			fprintf(stderr, "FIXME: too many luns\n");
			exit(-1);
		}
		nr_luns++;
	}

done:
	*((uint32_t *) data) = cpu_to_be32(nr_luns * 8);
	*len = min(oalen, nr_luns * 8 + 8);

	return result;
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
		cpu_to_be32(0xffffffff) : cpu_to_be32(size - 1);
	data[1] = cpu_to_be32(1U << BLK_SHIFT);
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
	data64[0] = cpu_to_be64(size - 1);
	data[2] = cpu_to_be32(1UL << BLK_SHIFT);

	*len = 32;

	return SAM_STAT_GOOD;
}

static int mmap_device(uint8_t *scb, int *len, int fd, uint32_t datalen, unsigned long *uaddr,
		       uint64_t *offset)
{
	void *p;
	uint64_t off;
	*len = 0;
	int err = SAM_STAT_GOOD;

	switch (scb[0]) {
	case READ_6:
	case WRITE_6:
		off = ((scb[1] & 0x1f) << 16) + (scb[2] << 8) + scb[3];
		break;
	case READ_10:
	case WRITE_10:
	case WRITE_VERIFY:
		off = be32_to_cpu(*(uint32_t *) &scb[2]);
		break;
	case READ_16:
	case WRITE_16:
		off = be64_to_cpu(*(uint64_t *) &scb[2]);
		break;
	default:
		off = 0;
		break;
	}

	off <<= BLK_SHIFT;

	if (*uaddr)
		*uaddr = *uaddr + off;
	else {
		p = mmap64(NULL, pgcnt(datalen, off) << PAGE_SHIFT,
			   PROT_READ | PROT_WRITE, MAP_SHARED, fd,
			   off & ~((1ULL << PAGE_SHIFT) - 1));

		*uaddr = (unsigned long) p + (off & ~PAGE_MASK);
		if (p == MAP_FAILED) {
			err = SAM_STAT_CHECK_CONDITION;
			eprintf("%lx %u %" PRIu64 "\n", *uaddr, datalen, off);
		}
	}
	*offset = off;
	*len = datalen;
	printf("%lx %u %" PRIu64 "\n", *uaddr, datalen, off);

	return err;
}

static inline int mmap_cmd_init(uint8_t *scb, uint8_t *rw)
{
	int result = 1;

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
		result = 0;
	}
	return result;
}

#define        TGT_INVALID_DEV_ID      ~0ULL

uint64_t scsi_get_devid(uint8_t *p)
{
	uint64_t lun = TGT_INVALID_DEV_ID;

	/* ibmvstgt hack */
	lun = *((uint64_t *) p);
	dprintf("%" PRIx64 " %u %u %u\n", lun, GETTARGET(lun), GETBUS(lun), GETLUN(lun));

	if (GETBUS(lun) || GETLUN(lun))
		return TGT_INVALID_DEV_ID;
	else
		return GETTARGET(lun);

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

int scsi_cmd_perform(int host_no, uint8_t *pdu, int *len,
		     uint32_t datalen, unsigned long *uaddr, uint8_t *rw,
		     uint8_t *try_map, uint64_t *offset, uint8_t *lun_buf,
		     struct tgt_device *dev, struct list_head *dev_list)
{
	int result = SAM_STAT_GOOD;
	uint8_t *data = NULL, *scb = pdu;
	uint64_t lun;

	lun = scsi_get_devid(lun_buf);

	dprintf("%" PRIu64 " %x %u\n", lun, scb[0], datalen);

	*offset = 0;
	if (!mmap_cmd_init(scb, rw))
		data = valloc(PAGE_SIZE);

	if (!dev)
		switch (scb[0]) {
		case REQUEST_SENSE:
		case INQUIRY:
		case REPORT_LUNS:
			break;
		default:
			*offset = 0;
			if (!data)
				data = valloc(PAGE_SIZE);
			*len = sense_data_build(data, 0x70, ILLEGAL_REQUEST,
						0x25, 0);
			result = SAM_STAT_CHECK_CONDITION;
			goto out;
		}

	switch (scb[0]) {
	case INQUIRY:
		result = inquiry(dev, host_no, lun_buf, scb, data, len);
		break;
	case REPORT_LUNS:
		result = report_luns(dev_list, lun_buf, scb, data, len);
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
		result = mmap_device(scb, len, dev->fd, datalen,
				     uaddr, offset);
		if (result == SAM_STAT_GOOD)
			*try_map = 1;
		else {
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
		eprintf("BUG? %u %" PRIu64 "\n", scb[0], lun);
		*len = 0;
		break;
	}

out:
	if (data)
		*uaddr = (unsigned long) data;

	return result;
}
