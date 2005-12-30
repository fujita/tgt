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
#include <scsi/scsi_cmnd.h>

#include <tgt.h>
#include <tgt_device.h>
#include <tgt_protocol.h>
#include <tgt_target.h>
#include <tgt_scsi_if.h>

static kmem_cache_t *tgt_scsi_cmd_cache;

static inline struct tgt_scsi_cmd *tgt_cmd_to_scsi(struct tgt_cmd *cmd)
{
	return (struct tgt_scsi_cmd *) cmd->proto_priv;
}

static void
scsi_tgt_cmd_create(struct tgt_cmd *cmd, uint8_t *scb,
		    uint32_t data_len, enum dma_data_direction data_dir,
		    uint8_t *lun, int lun_size, int tags)
{
	struct tgt_scsi_cmd *scmd;

	scmd = tgt_cmd_to_scsi(cmd);
	memcpy(scmd->scb, scb, sizeof(scmd->scb));
	memcpy(scmd->lun, lun, sizeof(scmd->lun));
	scmd->tags = tags;

	/* is this device specific */
	cmd->data_dir = data_dir;
	/*
	 * set bufflen based on data_len for now, but let device specific
	 * handler overide just in case
	 */
	cmd->bufflen = data_len;
}

static void scsi_tgt_uspace_pdu_build(struct tgt_cmd *cmd, void *data)
{
	struct tgt_scsi_cmd *scmd = tgt_cmd_to_scsi(cmd);
	memcpy(data, scmd, sizeof(struct tgt_scsi_cmd));
}

static void scsi_tgt_uspace_cmd_complete(struct tgt_cmd *cmd)
{
	struct tgt_scsi_cmd *scmd = tgt_cmd_to_scsi(cmd);

	dprintk("res %d, cmd %p op 0x%02x %lx\n", cmd->result, cmd, scmd->scb[0],
		cmd->uaddr);
}

static struct tgt_protocol scsi_tgt_proto = {
	.name = "scsi",
	.module = THIS_MODULE,
	.cmd_create = scsi_tgt_cmd_create,
	.uspace_pdu_build = scsi_tgt_uspace_pdu_build,
	.uspace_cmd_complete = scsi_tgt_uspace_cmd_complete,
	.uspace_pdu_size = sizeof(struct tgt_scsi_cmd),
};

static int __init scsi_tgt_init(void)
{
	int err;
	size_t size = sizeof(struct tgt_cmd) + sizeof(struct tgt_scsi_cmd);

	tgt_scsi_cmd_cache = kmem_cache_create("tgt_scsi_cmd",
					       size, 0,
					       SLAB_HWCACHE_ALIGN | SLAB_NO_REAP,
					       NULL, NULL);
	if (!tgt_scsi_cmd_cache)
		return -ENOMEM;
	scsi_tgt_proto.cmd_cache = tgt_scsi_cmd_cache;

	err = tgt_protocol_register(&scsi_tgt_proto);
	if (err)
		goto cache_destroy;

	return 0;
cache_destroy:
	kmem_cache_destroy(tgt_scsi_cmd_cache);

	return err;
}

static void __exit scsi_tgt_exit(void)
{
	kmem_cache_destroy(tgt_scsi_cmd_cache);
	tgt_protocol_unregister(&scsi_tgt_proto);
}

module_init(scsi_tgt_init);
module_exit(scsi_tgt_exit);
MODULE_LICENSE("GPL");
