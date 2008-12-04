/*
 * SCSI command processing specific to IBM Virtual SCSI target Driver
 *
 * Copyright (C) 2005-2007 FUJITA Tomonori <tomof@acm.org>
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
#include <sys/mman.h>

#include "list.h"
#include "util.h"
#include "tgtd.h"
#include "target.h"
#include "driver.h"
#include "spc.h"
#include "scsi.h"

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

static int __ibmvio_inquiry(int host_no, struct scsi_cmd *cmd, uint8_t *data)
{
	struct inquiry_data *id = (struct inquiry_data *) data;
	char system_id[256], path[256], buf[32];
	int fd, err, partition_number;
	unsigned int unit_address;
	unsigned char device_type;
	uint64_t lun = *((uint64_t *) cmd->lun);

	device_type = (cmd->dev->attrs.qualifier & 0x7 ) << 5;
	device_type |= (cmd->dev->attrs.device_type & 0x1f);

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

	id->qual_type = device_type;
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
	if (device_type)
		memcpy(id->product, "VOPTA blkdev    ", 16);
	else
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

static int ibmvio_inquiry(int host_no, struct scsi_cmd *cmd)
{
	uint8_t *data, *scb = cmd->scb;
	unsigned char key = ILLEGAL_REQUEST;
	uint16_t asc = ASC_INVALID_FIELD_IN_CDB;
	uint32_t len;

	if (((scb[1] & 0x3) == 0x3) || (!(scb[1] & 0x3) && scb[2]))
		goto sense;

	dprintf("%x %x\n", scb[1], scb[2]);

	if (scb[1] & 0x3)
		return spc_inquiry(host_no, cmd);

	data = scsi_get_in_buffer(cmd);

	len = __ibmvio_inquiry(host_no, cmd, data);
	len = min_t(int, len, scb[4]);

	scsi_set_in_resid_by_actual(cmd, len);

	if (cmd->dev->lun != cmd->dev_id)
		data[0] = TYPE_NO_LUN;

	return SAM_STAT_GOOD;
sense:
	scsi_set_in_resid_by_actual(cmd, 0);
	sense_data_build(cmd, key, asc);
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

static int ibmvio_report_luns(int host_no, struct scsi_cmd *cmd)
{
	struct scsi_lu *lu;
	struct list_head *dev_list = &cmd->c_target->device_list;
	uint64_t lun, *data;
	int idx, alen, oalen, nr_luns, rbuflen = 4096;
	uint8_t *lun_buf = cmd->lun;
	unsigned char key = ILLEGAL_REQUEST;
	uint16_t asc = ASC_INVALID_FIELD_IN_CDB;

	alen = __be32_to_cpu(*(uint32_t *)&cmd->scb[6]);
	if (alen < 16)
		goto sense;

	data = scsi_get_in_buffer(cmd);

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

	list_for_each_entry(lu, dev_list, device_siblings) {
		lun = lu->lun;
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
	scsi_set_in_resid_by_actual(cmd, min(oalen, nr_luns * 8 + 8));
	return SAM_STAT_GOOD;
sense:
	scsi_set_in_resid_by_actual(cmd, 0);
	sense_data_build(cmd, key, asc);
	return SAM_STAT_CHECK_CONDITION;
}

#define        TGT_INVALID_DEV_ID      ~0ULL

static uint64_t scsi_lun_to_int(uint8_t *p)
{
	uint64_t lun = TGT_INVALID_DEV_ID;

	lun = *((uint64_t *) p);
	dprintf("%" PRIx64 " %u %u %u\n", lun, GETTARGET(lun), GETBUS(lun), GETLUN(lun));

	if (GETBUS(lun) || GETLUN(lun))
		return TGT_INVALID_DEV_ID;
	else
		return GETTARGET(lun);
}

static int ibmvio_lu_create(struct scsi_lu *lu)
{
	struct device_type_operations *ops =  lu->dev_type_template.ops;

	ops[INQUIRY].cmd_perform = ibmvio_inquiry;
	ops[REPORT_LUNS].cmd_perform = ibmvio_report_luns;

	return 0;
}

static struct tgt_driver ibmvio = {
	.name			= "ibmvio",
	.use_kernel		= 1,
	.scsi_get_lun		= scsi_lun_to_int,
	.lu_create		= ibmvio_lu_create,
	.cmd_end_notify		= kspace_send_cmd_res,
	.mgmt_end_notify	= kspace_send_tsk_mgmt_res,
	.default_bst		= "mmap",
};

__attribute__((constructor)) static void ibmvio_driver_constructor(void)
{
	register_driver(&ibmvio);
}
