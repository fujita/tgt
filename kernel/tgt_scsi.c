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
tgt_scsi_cmd_create(struct tgt_cmd *cmd, uint8_t *scb,
		    uint32_t data_len, enum dma_data_direction data_dir,
		    uint8_t *lun, int lun_size, int tags)
{
	struct tgt_scsi_cmd *scmd = tgt_cmd_to_scsi(cmd);

	memcpy(scmd->scb, scb, sizeof(scmd->scb));
	memcpy(scmd->lun, lun, sizeof(scmd->lun));
	scmd->tags = tags;

	cmd->data_dir = data_dir;
	/*
	 * set bufflen based on data_len for now, but let device specific
	 * handler overide just in case
	 */
	cmd->bufflen = data_len;
}

static void tgt_scsi_pdu_build(struct tgt_cmd *cmd, void *data)
{
	struct tgt_scsi_cmd *scmd = tgt_cmd_to_scsi(cmd);

	memcpy(data, scmd, sizeof(struct tgt_scsi_cmd));
}

static struct tgt_protocol tgt_scsi_proto = {
	.name = "scsi",
	.module = THIS_MODULE,
	.cmd_create = tgt_scsi_cmd_create,
	.uspace_pdu_build = tgt_scsi_pdu_build,
	.uspace_pdu_size = sizeof(struct tgt_scsi_cmd),
};

static int __init tgt_scsi_init(void)
{
	int err;
	size_t size = sizeof(struct tgt_cmd) + sizeof(struct tgt_scsi_cmd);

	tgt_scsi_cmd_cache = kmem_cache_create("tgt_scsi_cmd",
					       size, 0,
					       SLAB_HWCACHE_ALIGN | SLAB_NO_REAP,
					       NULL, NULL);
	if (!tgt_scsi_cmd_cache)
		return -ENOMEM;
	tgt_scsi_proto.cmd_cache = tgt_scsi_cmd_cache;

	err = tgt_protocol_register(&tgt_scsi_proto);
	if (err)
		goto cache_destroy;

	return 0;
cache_destroy:
	kmem_cache_destroy(tgt_scsi_cmd_cache);

	return err;
}

static void __exit tgt_scsi_exit(void)
{
	kmem_cache_destroy(tgt_scsi_cmd_cache);
	tgt_protocol_unregister(&tgt_scsi_proto);
}

module_init(tgt_scsi_init);
module_exit(tgt_scsi_exit);
MODULE_LICENSE("GPL");
