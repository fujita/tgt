/*
 * SCSI target protocol
 *
 * (C) 2005 FUJITA Tomonori <tomof@acm.org>
 * (C) 2005 Mike Christie <michaelc@cs.wisc.edu>
 * This code is licenced under the GPL.
 */
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <scsi/scsi.h>
#include <scsi/scsi_tcq.h>

#include <tgt.h>
#include <tgt_scsi.h>
#include <tgt_device.h>
#include <tgt_protocol.h>
#include <tgt_target.h>

static kmem_cache_t *scsi_tgt_cmd_cache;

/*
 * we should be able to use scsi-ml's functions for this
 */
static uint64_t scsi_tgt_translate_lun(uint8_t *p, int size)
{
	uint64_t lun = ~0ULL;

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
static void
scsi_tgt_cmd_create(struct tgt_cmd *cmd, uint8_t *scb,
		    uint32_t data_len, enum dma_data_direction data_dir,
		    uint8_t *lun, int lun_size, int tags)
{
	struct scsi_tgt_cmd *scmd;

	/* translate target driver LUN to device id */
	cmd->dev_id = scsi_tgt_translate_lun(lun, lun_size);
	scmd = tgt_cmd_to_scsi(cmd);
	memcpy(scmd->scb, scb, sizeof(scmd->scb));
	scmd->tags = tags;

	/* is this device specific */
	cmd->data_dir = data_dir;
	/*
	 * set bufflen based on data_len for now, but let device specific
	 * handler overide just in case
	 */
	cmd->bufflen = data_len;
}

/* uspace command failure */
int scsi_tgt_sense_copy(struct tgt_cmd *cmd)
{
	struct scsi_tgt_cmd *scmd = tgt_cmd_to_scsi(cmd);
	uint8_t *data = scmd->sense_buff;
	int len;

	memset(data, 0, sizeof(scmd->sense_buff));
	len = min_t(int, cmd->bufflen, sizeof(scmd->sense_buff));

	/* userspace did everything for us */
	memcpy(data, page_address(cmd->sg[0].page), len);
	scmd->sense_len = len;

	return len;
}
EXPORT_SYMBOL_GPL(scsi_tgt_sense_copy);

static void scsi_tgt_uspace_pdu_build(struct tgt_cmd *cmd, void *data)
{
	struct scsi_tgt_cmd *scmd = (struct scsi_tgt_cmd *)cmd->proto_priv;
	memcpy(data, scmd->scb, sizeof(scmd->scb));
}

static void scsi_tgt_uspace_cmd_complete(struct tgt_cmd *cmd)
{
	struct scsi_tgt_cmd *scmd = tgt_cmd_to_scsi(cmd);

	dprintk("%d %lu\n", cmd->result, cmd->uaddr);

	if (cmd->result != SAM_STAT_GOOD)
		scsi_tgt_sense_copy(cmd);

	dprintk("res %d, cmd %p op 0x%02x\n", cmd->result, cmd, scmd->scb[0]);
}

static struct tgt_protocol scsi_tgt_proto = {
	.name = "scsi",
	.module = THIS_MODULE,
	.cmd_create = scsi_tgt_cmd_create,
	.uspace_pdu_build = scsi_tgt_uspace_pdu_build,
	.uspace_cmd_complete = scsi_tgt_uspace_cmd_complete,
	.uspace_pdu_size = MAX_COMMAND_SIZE,
};

static int __init scsi_tgt_init(void)
{
	int err;
	size_t size = sizeof(struct tgt_cmd) + sizeof(struct scsi_tgt_cmd);

	scsi_tgt_cmd_cache = kmem_cache_create("scsi_tgt_cmd",
					       size, 0,
					       SLAB_HWCACHE_ALIGN | SLAB_NO_REAP,
					       NULL, NULL);
	if (!scsi_tgt_cmd_cache)
		return -ENOMEM;
	scsi_tgt_proto.cmd_cache = scsi_tgt_cmd_cache;

	err = tgt_protocol_register(&scsi_tgt_proto);
	if (err)
		goto cache_destroy;

	return 0;
cache_destroy:
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
