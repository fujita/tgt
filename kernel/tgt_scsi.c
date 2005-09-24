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

static kmem_cache_t *scsi_tgt_cmd_cache;

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
static struct tgt_cmd *
scsi_tgt_create_cmd(struct tgt_session *session, uint8_t *scb,
		     uint32_t data_len, enum dma_data_direction data_dir,
		     uint8_t *lun, int lun_size,
		     void (*done)(struct tgt_cmd *))
{
	struct tgt_device *device;
	struct tgt_cmd *cmd;
	struct scsi_tgt_cmd *scmd;

	cmd = tgt_cmd_create(session);
	if (!cmd) {
		printk(KERN_ERR "Could not allocate command\n");
		return NULL;
	}
	scmd = tgt_cmd_to_scsi(cmd);
	memcpy(scmd->scb, scb, sizeof(scmd->scb));

	/* translate target driver LUN to device id */
	cmd->dev_id = scsi_tgt_translate_lun(lun, lun_size);
	device = tgt_device_find(session->target, cmd->dev_id);
	if (!device) {
		printk(KERN_ERR "Could not find device if %llu\n",
		       cmd->dev_id);
		return NULL;
	}
	cmd->device = device;

	/* is this device specific */
	cmd->data_dir = data_dir;
	/*
	 * set bufflen based on data_len for now, but let device specific
	 * handler overide just in case
	 */
	cmd->bufflen = data_len;
	/* do scsi device specific setup */
	device->dt->prep_cmd(cmd, data_len);
	if (cmd->bufflen)
		tgt_cmd_alloc_buffer(cmd, done);
	return cmd;
}

/* kspace command failure */
int scsi_tgt_sense_data_build(struct tgt_cmd *cmd, uint8_t key,
			      uint8_t ascode, uint8_t ascodeq)
{
	struct scsi_tgt_cmd *scmd = tgt_cmd_to_scsi(cmd);
	int len = 8, alen = 6;
	uint8_t *data = scmd->sense_buff;

	memset(data, 0, sizeof(scmd->sense_buff));

	data[0] = 0x70 | 1U << 7;
	data[2] = key;
	data[7] = alen;
	data[12] = ascode;
	data[13] = ascodeq;
	cmd->result = SAM_STAT_CHECK_CONDITION;
	scmd->sense_len = len + alen;

	return len + alen;
}
EXPORT_SYMBOL_GPL(scsi_tgt_sense_data_build);

/* uspace command failure */
int scsi_tgt_sense_copy(struct tgt_cmd *cmd)
{
	struct scsi_tgt_cmd *scmd = tgt_cmd_to_scsi(cmd);
	uint8_t *data = scmd->sense_buff;
	int len;

	memset(data, 0, sizeof(scmd->sense_buff));
	len = min(cmd->bufflen, sizeof(scmd->sense_buff));

	/* userspace did everything for us */
	memcpy(data, page_address(cmd->sg[0].page), len);
	scmd->sense_len = len;

	return len;
}
EXPORT_SYMBOL_GPL(scsi_tgt_sense_copy);

void scsi_tgt_build_uspace_pdu(struct tgt_cmd *cmd, void *data)
{
	struct scsi_tgt_cmd *scmd = (struct scsi_tgt_cmd *)cmd->proto_priv;
	memcpy(data, scmd->scb, sizeof(scmd->scb));
}

static struct tgt_protocol scsi_tgt_proto = {
	.name = "scsi",
	.module = THIS_MODULE,
	.create_cmd = scsi_tgt_create_cmd,
	.destroy_cmd = tgt_cmd_destroy,
	.queue_cmd = tgt_cmd_queue,
	.build_uspace_pdu = scsi_tgt_build_uspace_pdu,
	.uspace_pdu_size = MAX_COMMAND_SIZE,
};

static int __init scsi_tgt_init(void)
{
	int err;

	scsi_tgt_cmd_cache = kmem_cache_create("scsi_tgt_cmd",
			sizeof(struct tgt_cmd) + sizeof(struct scsi_tgt_cmd),
			0, SLAB_HWCACHE_ALIGN | SLAB_NO_REAP, NULL, NULL);
	if (!scsi_tgt_cmd_cache)
		return -ENOMEM;
	scsi_tgt_proto.cmd_cache = scsi_tgt_cmd_cache;

	err = tgt_protocol_register(&scsi_tgt_proto);
	if (err)
		kmem_cache_destroy(scsi_tgt_cmd_cache);

	return err;
}

static void __exit scsi_tgt_exit(void)
{
	kmem_cache_destroy(scsi_tgt_cmd_cache);
	tgt_protocol_unregister(&scsi_tgt_proto);
}

module_init(scsi_tgt_init);
module_exit(scsi_tgt_exit);
MODULE_LICENSE("GPL");
