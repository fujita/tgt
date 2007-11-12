/*
 * SCSI primary command processing
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
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "list.h"
#include "util.h"
#include "tgtd.h"
#include "parser.h"
#include "target.h"
#include "driver.h"
#include "tgtadm_error.h"
#include "scsi.h"
#include "spc.h"

#define PRODUCT_REV	"0"
#define BLK_SHIFT	9

/*
 * Protocol Identifier Values
 *
 * 0 Fibre Channel (FCP-2)
 * 1 Parallel SCSI (SPI-5)
 * 2 SSA (SSA-S3P)
 * 3 IEEE 1394 (SBP-3)
 * 4 SCSI Remote Direct Memory Access (SRP)
 * 5 iSCSI
 * 6 SAS Serial SCSI Protocol (SAS)
 * 7 Automation/Drive Interface (ADT)
 * 8 AT Attachment Interface (ATA/ATAPI-7)
 */
#define PIV_FCP 0
#define PIV_SPI 1
#define PIV_S3P 2
#define PIV_SBP 3
#define PIV_SRP 4
#define PIV_ISCSI 5
#define PIV_SAS 6
#define PIV_ADT 7
#define PIV_ATA 8

#define PIV_VALID 0x80

/*
 * Code Set
 *
 *  1 - Designator fild contains binary values
 *  2 - Designator field contains ASCII printable chars
 *  3 - Designaotor field contains UTF-8
 */
#define INQ_CODE_BIN 1
#define INQ_CODE_ASCII 2
#define INQ_CODE_UTF8 3

/*
 * Association field
 *
 * 00b - Associated with Logical Unit
 * 01b - Associated with target port
 * 10b - Associated with SCSI Target device
 * 11b - Reserved
 */
#define ASS_LU	0
#define ASS_TGT_PORT 0x10
#define ASS_TGT_DEV 0x20

/*
 * Designator type - SPC-4 Reference
 *
 * 0 - Vendor specific - 7.6.3.3
 * 1 - T10 vendor ID - 7.6.3.4
 * 2 - EUI-64 - 7.6.3.5
 * 3 - NAA - 7.6.3.6
 * 4 - Relative Target port identifier - 7.6.3.7
 * 5 - Target Port group - 7.6.3.8
 * 6 - Logical Unit group - 7.6.3.9
 * 7 - MD5 logical unit identifier - 7.6.3.10
 * 8 - SCSI name string - 7.6.3.11
 */
#define DESG_VENDOR 0
#define DESG_T10 1
#define DESG_EUI64 2
#define DESG_NAA 3
#define DESG_REL_TGT_PORT 4
#define DESG_TGT_PORT_GRP 5
#define DESG_LU_GRP 6
#define DESG_MD5 7
#define DESG_SCSI 8

void update_vpd_80(struct scsi_lu *lu, void *sn)
{
	struct vpd *vpd_pg = lu->attrs.lu_vpd[0];
	char *data = (char *)vpd_pg->data;

	memset(data, 0x20, vpd_pg->size);

	if (strlen(sn)) {
		int tmp = strlen(sn);
		char *p, *q;

		p = data + vpd_pg->size - 1;
		q = sn + tmp - 1;
		for (; tmp > 0; tmp--, q)
			*(p--) = *(q--);
	}
}

void update_vpd_83(struct scsi_lu *lu, void *id)
{
	struct vpd *vpd_pg = lu->attrs.lu_vpd[3];
	uint8_t	*data = vpd_pg->data;

	data[0] = (PIV_ISCSI << 4) | INQ_CODE_ASCII;
	data[1] = PIV_VALID | ASS_TGT_PORT | DESG_VENDOR;
	data[3] = SCSI_ID_LEN;

	strncpy((char *)data + 4, id, SCSI_ID_LEN);
}

int spc_inquiry(int host_no, struct scsi_cmd *cmd)
{
	int len = 0, ret = SAM_STAT_CHECK_CONDITION;
	uint8_t *data;
	uint8_t *scb = cmd->scb;
	unsigned char key = ILLEGAL_REQUEST;
	uint16_t asc = ASC_INVALID_FIELD_IN_CDB;
	uint8_t devtype = 0;
	struct lu_phy_attr *attrs;
	struct vpd *vpd_pg;

	if (((scb[1] & 0x3) == 0x3) || (!(scb[1] & 0x3) && scb[2]))
		goto sense;

	data = scsi_get_read_buffer(cmd);

	dprintf("%x %x\n", scb[1], scb[2]);

	attrs = &cmd->dev->attrs;

	devtype = (attrs->qualifier & 0x7) << 5;
	devtype |= (attrs->device_type & 0x1f);

	if (!(scb[1] & 0x3)) {
		int i;
		uint16_t *desc;

		data[0] = devtype;
		data[1] = (attrs->removable) ? 0x80 : 0;
		data[2] = 5;	/* SPC-3 */
		data[3] = 0x42;
		data[7] = 0x02;

		memset(data + 8, 0x20, 28);
		strncpy((char *)data + 8, attrs->vendor_id, VENDOR_ID_LEN);
		strncpy((char *)data + 16, attrs->product_id, PRODUCT_ID_LEN);
		strncpy((char *)data + 32, attrs->product_rev, PRODUCT_REV_LEN);

		desc = (uint16_t *)(data + 58);
		for (i = 0; i < ARRAY_SIZE(attrs->version_desc); i++)
			*desc++ = __cpu_to_be16(attrs->version_desc[i]);

		data[4] = len - 5;	/* Additional Length */
		len = 66;
		ret = SAM_STAT_GOOD;
	} else if (scb[1] & 0x2) {
		/* CmdDt bit is set */
		/* We do not support it now. */
		data[1] = 0x1;
		data[5] = 0;
		len = 6;
		ret = SAM_STAT_GOOD;
	} else if (scb[1] & 0x1) {
		uint8_t pcode = scb[2];

		if (pcode == 0x00) {
			uint8_t *p;
			int i, cnt;

			data[0] = devtype;
			data[1] = 0;
			data[2] = 0;

			cnt = 1;
			p = data + 5;
			for (i = 0; i < ARRAY_SIZE(attrs->lu_vpd); i++) {
				if (attrs->lu_vpd[i]) {
					*p++ = i | 0x80;
					cnt++;
				}
			}
			data[3] = cnt;
			data[4] = 0x0;
			len = cnt + 4;
			ret = SAM_STAT_GOOD;
		} else if (attrs->lu_vpd[PCODE_OFFSET(pcode)]) {
			vpd_pg = attrs->lu_vpd[PCODE_OFFSET(pcode)];

			data[0] = devtype;
			data[1] = pcode;
			data[2] = (vpd_pg->size >> 8);
			data[3] = vpd_pg->size & 0xff;
			memcpy(&data[4], vpd_pg->data, vpd_pg->size);
			len = vpd_pg->size + 4;
			ret = SAM_STAT_GOOD;
		}
	}

	if (ret != SAM_STAT_GOOD)
		goto sense;

	cmd->len = min_t(int, len, scb[4]);

	if (cmd->dev->lun != cmd->dev_id)
		data[0] = TYPE_NO_LUN;

	return SAM_STAT_GOOD;
sense:
	cmd->len = 0;
	sense_data_build(cmd, key, asc);
	return SAM_STAT_CHECK_CONDITION;
}

int spc_report_luns(int host_no, struct scsi_cmd *cmd)
{
	struct scsi_lu *lu;
	struct list_head *dev_list = &cmd->c_target->device_list;
	uint64_t lun, *data;
	int idx, alen, oalen, nr_luns, rbuflen = 4096, overflow;
	unsigned char key = ILLEGAL_REQUEST;
	uint16_t asc = ASC_INVALID_FIELD_IN_CDB;
	uint8_t *scb = cmd->scb;

	alen = (uint32_t)scb[6] << 24 | (uint32_t)scb[7] << 16 |
		(uint32_t)scb[8] << 8 | (uint32_t)scb[9];
	if (alen < 16)
		goto sense;

	data = scsi_get_read_buffer(cmd);

	alen &= ~(8 - 1);
	oalen = alen;

	alen -= 8;
	rbuflen -= 8; /* FIXME */
	idx = 1;
	nr_luns = 0;

	overflow = 0;
	list_for_each_entry(lu, dev_list, device_siblings) {
		nr_luns++;

		if (overflow)
			continue;

		lun = lu->lun;
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
	cmd->len = min(oalen, nr_luns * 8 + 8);
	return SAM_STAT_GOOD;
sense:
	cmd->len = 0;
	sense_data_build(cmd, key, asc);
	return SAM_STAT_CHECK_CONDITION;
}

int spc_start_stop(int host_no, struct scsi_cmd *cmd)
{
	cmd->len = 0;

	if (device_reserved(cmd))
		return SAM_STAT_RESERVATION_CONFLICT;
	else
		return SAM_STAT_GOOD;
}

int spc_test_unit(int host_no, struct scsi_cmd *cmd)
{
	/* how should we test a backing-storage file? */

	if (device_reserved(cmd))
		return SAM_STAT_RESERVATION_CONFLICT;
	if (cmd->dev->attrs.reset) {
		cmd->dev->attrs.reset = 0;
		sense_data_build(cmd, UNIT_ATTENTION, ASC_POWERON_RESET);
		return SAM_STAT_CHECK_CONDITION;
	}
	if (cmd->dev->attrs.online)
		return SAM_STAT_GOOD;
	if (cmd->dev->attrs.removable)
		sense_data_build(cmd, NOT_READY, ASC_MEDIUM_NOT_PRESENT);
	else
		sense_data_build(cmd, NOT_READY, ASC_BECOMING_READY);

	return SAM_STAT_CHECK_CONDITION;
}

/**
 * build_mode_page - static routine used by spc_mode_sense()
 * @data:	destination pointer
 * @m:		struct mode pointer (src of data)
 *
 * Description: Copy mode page data from list into SCSI data so it can
 * be returned to the initiator
 *
 * Returns number of bytes copied.
 */
static int build_mode_page(uint8_t *data, struct mode_pg *pg)
{
	uint8_t *p;
	int len;

	data[0] = pg->pcode;
	len = pg->pcode_size;
	data[1] = len;
	p = &data[2];
	len += 2;
	memcpy(p, pg->mode_data, pg->pcode_size);

	return len;
}

/**
 * spc_mode_sense - Implement SCSI op MODE SENSE(6) and MODE SENSE(10)
 *
 * Reference : SPC4r11
 * 6.11 - MODE SENSE(6)
 * 6.12 - MODE SENSE(10)
 */
int spc_mode_sense(int host_no, struct scsi_cmd *cmd)
{
	int len = 0;
	uint8_t *data = NULL, *scb, mode6, dbd, pcode, subpcode;
	uint16_t alloc_len;
	unsigned char key = ILLEGAL_REQUEST;
	uint16_t asc = ASC_INVALID_FIELD_IN_CDB;
	struct mode_pg *pg;

	scb = cmd->scb;
	mode6 = (scb[0] == 0x1a);
	dbd = scb[1] & 0x8; /* Disable Block Descriptors */
	pcode = scb[2] & 0x3f;
	subpcode = scb[3];

	/* Currently not implemented */
	if (subpcode)
		goto sense;

	data = scsi_get_read_buffer(cmd);

	if (mode6) {
		alloc_len = scb[4];
		len = 4;
	} else {
		alloc_len = (scb[7] << 8) + scb[8];
		len = 8;
	}

	if (alloc_len > pagesize)
		goto sense;

	if (!dbd) {
		memcpy(data + len, cmd->dev->mode_block_descriptor,
				BLOCK_DESCRIPTOR_LEN);
		len += 8;
	}

	if (pcode == 0x3f) {
		int i;
		for (i = 0; i < ARRAY_SIZE(cmd->dev->mode_pgs); i++) {
			pg = cmd->dev->mode_pgs[i];
			if (pg)
				len += build_mode_page(data + len, pg);
		}
	} else {
		pg = cmd->dev->mode_pgs[pcode];
		if (!pg)
			goto sense;
		len += build_mode_page(data + len, pg);
	}

	if (mode6) {
		data[0] = len - 1;
		data[3] = dbd ? 0 : BLOCK_DESCRIPTOR_LEN;
	} else {
		*(uint16_t *)(data) = __cpu_to_be16(len - 3);
		data[7] = dbd ? 0 : BLOCK_DESCRIPTOR_LEN;
	}

	cmd->len = len;
	return SAM_STAT_GOOD;

sense:
	cmd->len = 0;
	sense_data_build(cmd, key, asc);
	return SAM_STAT_CHECK_CONDITION;
}

int spc_request_sense(int host_no, struct scsi_cmd *cmd)
{
	cmd->len = 0;
	sense_data_build(cmd, NO_SENSE, NO_ADDITIONAL_SENSE);
	return SAM_STAT_GOOD;
}

struct vpd *alloc_vpd(uint16_t size)
{
	struct vpd *vpd_pg;

	vpd_pg = zalloc(sizeof(struct vpd) + size);
	if (!vpd_pg)
		return NULL;

	vpd_pg->size = size;

	return vpd_pg;
}

static struct mode_pg *alloc_mode_pg(uint8_t pcode, uint8_t subpcode,
				     uint16_t size)
{
	struct mode_pg *pg;

	pg = zalloc(sizeof(*pg) + size);
	if (!pg)
		return NULL;

	pg->pcode = pcode;
	pg->subpcode = subpcode;
	pg->pcode_size = size;

	return pg;
}

int add_mode_page(struct scsi_lu *lu, char *p)
{
	int i, tmp, ret = TGTADM_SUCCESS;
	uint8_t pcode, subpcode, *data;
	uint16_t size;
	struct mode_pg *pg;

	pcode = subpcode = i = size = 0;
	data = NULL;

	for (i = 0; p; i++) {
		switch (i) {
		case 0:
			pcode = strtol(p, NULL, 0);
			break;
		case 1:
			subpcode = strtol(p, NULL, 0);
			break;
		case 2:
			size = strtol(p, NULL, 0);

			if (lu->mode_pgs[pcode])
				free(lu->mode_pgs[pcode]);

			pg = alloc_mode_pg(pcode, subpcode, size);
			if (!pg) {
				ret = TGTADM_NOMEM;
				goto exit;
			}

			lu->mode_pgs[pcode] = pg;
			data = pg->mode_data;
			break;
		default:
			if (i < (size + 3)) {
				tmp = strtol(p, NULL, 0);
				if (tmp > UINT8_MAX)
					eprintf("Incorrect value %d "
						"Mode page %d (0x%02x), index: %d\n",
						tmp, pcode, subpcode, i - 3);
				data[i - 3] = (uint8_t)tmp;
			}
			break;
		}

		p = strchr(p, ':');
		if (p)
			p++;
	}

	if (i != size + 3) {
		ret = TGTADM_INVALID_REQUEST;
		eprintf("Mode Page %d (0x%02x): param_count %d != "
			"MODE PAGE size : %d\n", pcode, subpcode, i, size + 3);
	}
exit:
	return ret;
}

void dump_cdb(struct scsi_cmd *cmd)
{
	uint8_t *cdb = cmd->scb;

	switch(cmd->scb_len) {
	case 6:
		dprintf("SCSI CMD: %02x %02x %02x %02x %02d %02x\n",
			cdb[0], cdb[1], cdb[2], cdb[3], cdb[4], cdb[5]);
		break;
	case 10:
		dprintf("SCSI CMD: %02x %02x %02x %02x %02d %02x\n"
				" %02x %02x %02x %02x",
			cdb[0], cdb[1], cdb[2], cdb[3], cdb[4], cdb[5],
			cdb[6], cdb[7], cdb[8], cdb[9]);
		break;
	case 12:
		dprintf("SCSI CMD: %02x %02x %02x %02x %02d %02x"
				" %02x %02x %02x %02x %02x %02x\n",
			cdb[0], cdb[1], cdb[2], cdb[3], cdb[4], cdb[5],
			cdb[6], cdb[7], cdb[8], cdb[9], cdb[10], cdb[11]);
		break;
	case 16:
		dprintf("SCSI CMD: %02x %02x %02x %02x %02d %02x"
				" %02x %02x %02x %02x %02x %02x"
				" %02x %02x %02x %02x\n",
			cdb[0], cdb[1], cdb[2], cdb[3], cdb[4], cdb[5],
			cdb[6], cdb[7], cdb[8], cdb[9], cdb[10], cdb[11],
			cdb[12], cdb[13], cdb[14], cdb[15]);
		break;
	}
}

int spc_illegal_op(int host_no, struct scsi_cmd *cmd)
{
	dump_cdb(cmd);
	cmd->len = 0;
	sense_data_build(cmd, ILLEGAL_REQUEST, ASC_INVALID_OP_CODE);
	return SAM_STAT_CHECK_CONDITION;
}

enum {
	Opt_scsi_id, Opt_scsi_sn,
	Opt_vendor_id, Opt_product_id,
	Opt_product_rev, Opt_sense_format,
	Opt_removable, Opt_online,
	Opt_mode_page,
	Opt_err,
};

static match_table_t tokens = {
	{Opt_scsi_id, "scsi_id=%s"},
	{Opt_scsi_sn, "scsi_sn=%s"},
	{Opt_vendor_id, "vendor_id=%s"},
	{Opt_product_id, "product_id=%s"},
	{Opt_product_rev, "product_rev=%s"},
	{Opt_sense_format, "sense_format=%s"},
	{Opt_removable, "removable=%s"},
	{Opt_online, "online=%s"},
	{Opt_mode_page, "mode_page=%s"},
	{Opt_err, NULL},
};

int lu_config(struct scsi_lu *lu, char *params, match_fn_t *fn)
{
	int err = TGTADM_SUCCESS;
	char *p;
	char buf[256];
	struct lu_phy_attr *attrs;
	struct vpd **lu_vpd;

	attrs = &lu->attrs;
	lu_vpd = attrs->lu_vpd;

	if (!strncmp("targetOps", params, 9))
		params = params + 10;

	while ((p = strsep(&params, ",")) != NULL) {
		substring_t args[MAX_OPT_ARGS];
		int token;
		if (!*p)
			continue;
		token = match_token(p, tokens, args);
		switch (token) {
		case Opt_scsi_id:
			match_strncpy(attrs->scsi_id, &args[0],
				      sizeof(attrs->scsi_id));
			lu_vpd[3]->vpd_update(lu, attrs->scsi_id);
			break;
		case Opt_scsi_sn:
			match_strncpy(attrs->scsi_sn, &args[0],
				      sizeof(attrs->scsi_sn));
			lu_vpd[0]->vpd_update(lu, attrs->scsi_sn);
			break;
		case Opt_vendor_id:
			match_strncpy(attrs->vendor_id, &args[0],
				      sizeof(attrs->vendor_id));
			break;
		case Opt_product_id:
			match_strncpy(attrs->product_id, &args[0],
				      sizeof(attrs->product_id));
			break;
		case Opt_product_rev:
			match_strncpy(attrs->product_rev, &args[0],
				      sizeof(attrs->product_rev));
			break;
		case Opt_sense_format:
			match_strncpy(buf, &args[0], sizeof(buf));
			attrs->sense_format = atoi(buf);
			break;
		case Opt_removable:
			match_strncpy(buf, &args[0], sizeof(buf));
			attrs->removable = atoi(buf);
			break;
		case Opt_online:
			match_strncpy(buf, &args[0], sizeof(buf));
			attrs->online = atoi(buf);
			break;
		case Opt_mode_page:
			match_strncpy(buf, &args[0], sizeof(buf));
			err = add_mode_page(lu, buf);
			break;
		default:
			err |= fn ? fn(lu, p) : TGTADM_INVALID_REQUEST;
		}
	}
	return err;
}

int spc_lu_config(struct scsi_lu *lu, char *params)
{
	return lu_config(lu, params, NULL);
}

int spc_lu_init(struct scsi_lu *lu)
{
	struct vpd **lu_vpd = lu->attrs.lu_vpd;
	struct target *tgt = lu->tgt;
	int pg;

	lu->attrs.device_type = lu->dev_type_template.type;
	lu->attrs.qualifier = 0x0;

	snprintf(lu->attrs.vendor_id, sizeof(lu->attrs.vendor_id),
		 "%-16s", VENDOR_ID);
	snprintf(lu->attrs.product_rev, sizeof(lu->attrs.product_rev),
		 "%s", "0001");
	snprintf(lu->attrs.scsi_id, sizeof(lu->attrs.scsi_id),
		 "deadbeaf%d:%" PRIu64, tgt->tid, lu->lun);
	snprintf(lu->attrs.scsi_sn, sizeof(lu->attrs.scsi_sn),
		 "beaf%d%" PRIu64, tgt->tid, lu->lun);

	/* VPD page 0x80 */
	pg = PCODE_OFFSET(0x80);
	lu_vpd[pg] = alloc_vpd(SCSI_SN_LEN);
	lu_vpd[pg]->vpd_update = update_vpd_80;
	lu_vpd[pg]->vpd_update(lu, lu->attrs.scsi_sn);

	/* VPD page 0x83 */
	pg = PCODE_OFFSET(0x83);
	lu_vpd[pg] = alloc_vpd(SCSI_ID_LEN + 4);
	lu_vpd[pg]->vpd_update = update_vpd_83;
	lu_vpd[pg]->vpd_update(lu, lu->attrs.scsi_id);

	lu->attrs.removable = 0;
	lu->attrs.sense_format = 0;
	lu->attrs.online = 0;
	lu->attrs.reset = 1;

	return 0;
}

void spc_lu_exit(struct scsi_lu *lu)
{
	int i;
	struct vpd **lu_vpd = lu->attrs.lu_vpd;

	for (i = 0; i < ARRAY_SIZE(lu->attrs.lu_vpd); i++)
		if (lu_vpd[i])
			free(lu_vpd[i]);

}

