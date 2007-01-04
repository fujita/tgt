/*
 * SCSI command processing specific to IBM Virtual SCSI target Driver
 *
 * Copyright (C) 2005 FUJITA Tomonori <tomof@acm.org>
 *
 * Based on:
 *
 * IBM eServer i/pSeries Virtual SCSI Target Driver
 * Copyright (C) 2003-2005 Dave Boutcher (boutcher@us.ibm.com) IBM Corp.
 *			   Santiago Leon (santil@us.ibm.com) IBM Corp.
 *			   Linda Xie (lxie@us.ibm.com) IBM Corp.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA
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
#include <scsi/scsi.h>
#include <sys/mman.h>

#include "list.h"
#include "util.h"
#include "tgtd.h"

#define GETTARGET(x) ((int)((((uint64_t)(x)) >> 56) & 0x003f))
#define GETBUS(x) ((int)((((uint64_t)(x)) >> 53) & 0x0007))
#define GETLUN(x) ((int)((((uint64_t)(x)) >> 48) & 0x001f))

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

int scsi_inquiry(struct tgt_device *dev, int host_no, uint8_t *lun_buf,
		 uint8_t *scb, uint8_t *data, int *len)
{
	int result = SAM_STAT_CHECK_CONDITION;

	if (((scb[1] & 0x3) == 0x3) || (!(scb[1] & 0x3) && scb[2]))
		goto err;

	dprintf("%x %x\n", scb[1], scb[2]);

	if (!(scb[1] & 0x3)) {
		*len = ibmvstgt_inquiry(host_no, *((uint64_t *) lun_buf), data);
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

static uint64_t make_lun(unsigned int bus, unsigned int target, unsigned int lun)
{
	uint16_t result = (0x8000 |
			   ((target & 0x003f) << 8) |
			   ((bus & 0x0007) << 5) |
			   (lun & 0x001f));
	return ((uint64_t) result) << 48;
}

int scsi_report_luns(struct list_head *dev_list, uint8_t *lun_buf,
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

	if ((*((uint64_t *) lun_buf))) {
		nr_luns = 1;
		goto done;
	}

	alen -= 8;
	rbuflen -= 8; /* FIXME */
	idx = 2;
	nr_luns = 1;

	list_for_each_entry(dev, dev_list, d_list) {
		lun = dev->lun;
		lun = make_lun(0, lun & 0x003f, 0);
		data[idx++] = __cpu_to_be64(lun);
		if (!(alen -= 8))
			break;
		if (!(rbuflen -= 8)) {
			fprintf(stderr, "FIXME: too many luns\n");
			exit(-1);
		}
		nr_luns++;
	}

done:
	*((uint32_t *) data) = __cpu_to_be32(nr_luns * 8);
	*len = min(oalen, nr_luns * 8 + 8);

	return result;
}

#define        TGT_INVALID_DEV_ID      ~0ULL

uint64_t scsi_lun_to_int(uint8_t *p)
{
	uint64_t lun = TGT_INVALID_DEV_ID;

	lun = *((uint64_t *) p);
	dprintf("%" PRIx64 " %u %u %u\n", lun, GETTARGET(lun), GETBUS(lun), GETLUN(lun));

	if (GETBUS(lun) || GETLUN(lun))
		return TGT_INVALID_DEV_ID;
	else
		return GETTARGET(lun);
}
