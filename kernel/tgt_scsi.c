/*
 * SCSI target protocol
 *
 * (C) 2005 FUJITA Tomonori <tomof@acm.org>
 * (C) 2005 Mike Christie <michaelc@cs.wisc.edu>
 * This code is licenced under the GPL.
 */
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <scsi/scsi.h>
#include <scsi/scsi_cmnd.h>

#include <tgt.h>
#include <tgt_protocol.h>

struct scsi_tgt_cmnd {
	uint8_t scb[MAX_COMMAND_SIZE];
	uint8_t sense_buff[SCSI_SENSE_BUFFERSIZE];
	int tags;
};

/*
 * we should be able to use scsi-ml's functions for this
 */
static uint64_t scsi_tgt_translate_lun(uint8_t *p, int size)
{
	uint64_t lun = ~0U;

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

static void scsi_tgt_init_cmnd_buffer(struct tgt_cmnd *cmnd)
{
	struct scsi_tgt_cmnd *scsi_tgt_cmnd = cmnd->tgt_protocol_private;
	uint8_t *scb = scsi_tgt_cmnd->scb;
	uint64_t off = 0;
	uint32_t len = 0;

	/*
	 * set bufflen and offset
	 */
	switch (scb[0]) {
	case READ_6:
	case WRITE_6:
		off = ((scb[1] & 0x1f) << 16) + (scb[2] << 8) + scb[3];
		len = scb[4];
		if (!len)
			len = 256;
		break;
	case READ_10:
	case WRITE_10:
	case WRITE_VERIFY:
		off = be32_to_cpu(*(u32 *) &scb[2]);
		len = (scb[7] << 8) + scb[8];
		break;
	case READ_16:
	case WRITE_16:
		off = be64_to_cpu(*(u64 *)&scb[2]);
		len = be32_to_cpu(*(u32 *)&scb[10]);
		break;
	default:
		break;
	}

	off <<= 9;
	len <<= 9;

	cmnd->bufflen = len;
	cmnd->offset = off;
}

static void scsi_tgt_init_cmnd(struct tgt_cmnd *cmnd, uint8_t *proto_data,
			       uint8_t *id_buff, int buff_size)
{
	struct scsi_tgt_cmnd *scsi_tgt_cmnd = cmnd->tgt_protocol_private;
	uint8_t *scb = scsi_tgt_cmnd->scb;

	memcpy(scb, proto_data, sizeof(scsi_tgt_cmnd->scb));

	/* set operation */
	switch (scb[0]) {
	case READ_6:
	case READ_10:
	case READ_16:
		cmnd->rw = READ;
		break;
	case WRITE_6:
	case WRITE_10:
	case WRITE_16:
	case WRITE_VERIFY:
		cmnd->rw = WRITE;
		break;
	default:
		cmnd->rw = SPECIAL;
	};

	/* translate target driver LUN to device id */
	cmnd->dev_id = scsi_tgt_translate_lun(id_buff, buff_size);
}

static int sense_data_build(struct tgt_cmnd *cmnd, uint8_t key,
			    uint8_t ascode, uint8_t ascodeq)
{
	struct scsi_tgt_cmnd *scsi_tgt_cmnd = cmnd->tgt_protocol_private;
	int len = 8, alen = 6;
	uint8_t *data = scsi_tgt_cmnd->sense_buff;

	memset(data, 0, sizeof(scsi_tgt_cmnd->sense_buff));

	if (cmnd->rw == READ || cmnd->rw == WRITE) {
		/* kspace command failure */

		data[0] = 0x70 | 1U << 7;
		data[2] = key;
		data[7] = alen;
		data[12] = ascode;
		data[13] = ascodeq;
	} else {
		char *addr;
		/* uspace command failure */

		len = min(cmnd->bufflen, sizeof(scsi_tgt_cmnd->sense_buff));
		alen = 0;

		addr = kmap_atomic(cmnd->sg[0].page, KM_SOFTIRQ0);
		memcpy(data, addr, len);
		kunmap_atomic(addr, KM_SOFTIRQ0);
	}

	cmnd->error_buff = data;
	cmnd->error_buff_len = len + alen;

	return len + alen;
}

/*
 * TODO: better error handling
 * We should get ASC and ASCQ from the device code.
 */
static uint8_t error_to_sense_key(int err)
{
	uint8_t key;

	switch (err) {
	case -ENOMEM:
		key = ABORTED_COMMAND;
		break;
	case -EOVERFLOW:
		key = HARDWARE_ERROR;
		break;
	default:
		key = HARDWARE_ERROR;
		break;
	}

	return key;
}

static void scsi_tgt_cmnd_done(struct tgt_cmnd *cmnd, int err)
{
	if (err < 0) {
		uint8_t key;

		key = error_to_sense_key(err);
		sense_data_build(cmnd, key, 0, 0);
		cmnd->result = SAM_STAT_CHECK_CONDITION;
	} else
		cmnd->result = SAM_STAT_GOOD;
}

void scsi_tgt_build_uspace_pdu(struct tgt_cmnd *cmnd, void *data)
{
	struct scsi_tgt_cmnd *scsi_tgt_cmnd = cmnd->tgt_protocol_private;

	memcpy(data, scsi_tgt_cmnd->scb, sizeof(scsi_tgt_cmnd->scb));
}

static struct tgt_protocol scsi_tgt_proto = {
	.name = "scsi",
	.module = THIS_MODULE,
	.init_cmnd = scsi_tgt_init_cmnd,
	.init_cmnd_buffer = scsi_tgt_init_cmnd_buffer,
	.cmnd_done = scsi_tgt_cmnd_done,
	.build_uspace_pdu = scsi_tgt_build_uspace_pdu,
	.priv_cmd_data_size = sizeof(struct scsi_tgt_cmnd),
	.uspace_pdu_size = MAX_COMMAND_SIZE,
};

static int __init scsi_tgt_init(void)
{
	return tgt_protocol_register(&scsi_tgt_proto);
}

static void __exit scsi_tgt_exit(void)
{
	tgt_protocol_unregister(&scsi_tgt_proto);
}

module_init(scsi_tgt_init);
module_exit(scsi_tgt_exit);
MODULE_LICENSE("GPL");
