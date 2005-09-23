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
#include <tgt_scsi.h>
#include <tgt_device.h>
#include <tgt_protocol.h>

static kmem_cache_t *scsi_tgt_cmnd_cache;

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

/*
 * we may have to add a wrapper becuase people are passing the lun in
 * differently
 */
static struct tgt_cmnd *
scsi_tgt_create_cmnd(struct tgt_session *session, uint8_t *scb, uint8_t *lun,
		     int lun_size)
{
	struct tgt_device *device;
	struct tgt_cmnd *cmnd;
	struct scsi_tgt_cmnd *scmnd;

	cmnd = tgt_cmnd_create(session);
	if (!cmnd) {
		printk(KERN_ERR "Could not allocate command\n");
		return NULL;
	}
	scmnd = tgt_cmnd_to_scsi(cmnd);
	memcpy(scmnd->scb, scb, sizeof(scmnd->scb));

	/* translate target driver LUN to device id */
	cmnd->dev_id = scsi_tgt_translate_lun(lun, lun_size);
	device = tgt_device_find(session->target, cmnd->dev_id);
	if (!device) {
		printk(KERN_ERR "Could not find device if %llu\n",
		       cmnd->dev_id);
		return NULL;
	}
	cmnd->device = device;

	/* do scsi device specific setup */
	device->dt->prep_cmnd(cmnd);
	return cmnd;
}

/* kspace command failure */
int scsi_tgt_sense_data_build(struct tgt_cmnd *cmnd, uint8_t key,
			      uint8_t ascode, uint8_t ascodeq)
{
	struct scsi_tgt_cmnd *scmnd = tgt_cmnd_to_scsi(cmnd);
	int len = 8, alen = 6;
	uint8_t *data = scmnd->sense_buff;

	memset(data, 0, sizeof(scmnd->sense_buff));

	data[0] = 0x70 | 1U << 7;
	data[2] = key;
	data[7] = alen;
	data[12] = ascode;
	data[13] = ascodeq;
	cmnd->result = SAM_STAT_CHECK_CONDITION;
	scmnd->sense_len = len + alen;

	return len + alen;
}
EXPORT_SYMBOL_GPL(scsi_tgt_sense_data_build);

/* uspace command failure */
int scsi_tgt_sense_copy(struct tgt_cmnd *cmnd)
{
	struct scsi_tgt_cmnd *scmnd = tgt_cmnd_to_scsi(cmnd);
	uint8_t *data = scmnd->sense_buff;
	int len;

	memset(data, 0, sizeof(scmnd->sense_buff));
	len = min(cmnd->bufflen, sizeof(scmnd->sense_buff));

	/* userspace did everything for us */
	memcpy(data, page_address(cmnd->sg[0].page), len);
	scmnd->sense_len = len;

	return len;
}
EXPORT_SYMBOL_GPL(scsi_tgt_sense_copy);

void scsi_tgt_build_uspace_pdu(struct tgt_cmnd *cmnd, void *data)
{
	struct scsi_tgt_cmnd *scmnd = (struct scsi_tgt_cmnd *)cmnd->proto_priv;
	memcpy(data, scmnd->scb, sizeof(scmnd->scb));
}

static struct tgt_protocol scsi_tgt_proto = {
	.name = "scsi",
	.module = THIS_MODULE,
	.create_cmnd = scsi_tgt_create_cmnd,
	.destroy_cmnd = tgt_cmnd_destroy,
	.alloc_cmnd_buffer = tgt_cmnd_alloc_buffer,
	.queue_cmnd = tgt_cmnd_queue,
	.build_uspace_pdu = scsi_tgt_build_uspace_pdu,
	.uspace_pdu_size = MAX_COMMAND_SIZE,
};

static int __init scsi_tgt_init(void)
{
	int err;

	scsi_tgt_cmnd_cache = kmem_cache_create("scsi_tgt_cmnd",
			sizeof(struct tgt_cmnd) + sizeof(struct scsi_tgt_cmnd),
			0, SLAB_HWCACHE_ALIGN | SLAB_NO_REAP, NULL, NULL);
	if (!scsi_tgt_cmnd_cache)
		return -ENOMEM;
	scsi_tgt_proto.cmnd_cache = scsi_tgt_cmnd_cache;

	err = tgt_protocol_register(&scsi_tgt_proto);
	if (err)
		kmem_cache_destroy(scsi_tgt_cmnd_cache);

	return err;
}

static void __exit scsi_tgt_exit(void)
{
	kmem_cache_destroy(scsi_tgt_cmnd_cache);
	tgt_protocol_unregister(&scsi_tgt_proto);
}

module_init(scsi_tgt_init);
module_exit(scsi_tgt_exit);
MODULE_LICENSE("GPL");
