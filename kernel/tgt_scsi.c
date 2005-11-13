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

enum scsi_tgt_device_state_bit {
	STDEV_ORDERED,
	STDEV_HEAD,
};

/*
 * The ordering stuff can be generic for all protocols. If so, should
 * these be moved into struct tgt_device?
 */
struct scsi_tgt_device {
	spinlock_t lock;
	struct list_head pending_cmds;
	unsigned long state;
	unsigned active_cmds;
};

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
static struct tgt_cmd *
scsi_tgt_create_cmd(struct tgt_session *session, void *tgt_priv, uint8_t *scb,
		    uint32_t data_len, enum dma_data_direction data_dir,
		    uint8_t *lun, int lun_size, int tags)
{
	struct tgt_device *device;
	struct tgt_cmd *cmd;
	struct scsi_tgt_cmd *scmd;

	cmd = tgt_cmd_create(session, tgt_priv);
	if (!cmd) {
		printk(KERN_ERR "Could not allocate command\n");
		return NULL;
	}
	scmd = tgt_cmd_to_scsi(cmd);
	memcpy(scmd->scb, scb, sizeof(scmd->scb));
	scmd->tags = tags;

	/* translate target driver LUN to device id */
	cmd->dev_id = scsi_tgt_translate_lun(lun, lun_size);
	device = tgt_device_find(session->target, cmd->dev_id);
	if (!device) {
		switch (scmd->scb[0]) {
		case INQUIRY:
		case REPORT_LUNS:
			/* we assume that we have lun 0. */
			device = tgt_device_find(session->target, 0);
			break;
		}

		if (!device) {
			eprintk("Could not find device %x %" PRIu64 "\n",
				scmd->scb[0], cmd->dev_id);
			/*
			 * TODO: FIX THIS LEAK. We should check magic
			 * target queue.
			 */
			return NULL;
		}
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

	tgt_cmd_start(cmd);

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
	len = min_t(int, cmd->bufflen, sizeof(scmd->sense_buff));

	/* userspace did everything for us */
	memcpy(data, page_address(cmd->sg[0].page), len);
	scmd->sense_len = len;

	return len;
}
EXPORT_SYMBOL_GPL(scsi_tgt_sense_copy);

#define	device_blocked(x)	((x)->state & (1 << STDEV_ORDERED | 1 << STDEV_HEAD))

static int scsi_tgt_task_state(struct tgt_cmd *cmd, int queue, int *more)
{
	struct tgt_device *device = cmd->device;
	struct scsi_tgt_device *stdev = device->pt_data;
	struct scsi_tgt_cmd *scmd = tgt_cmd_to_scsi(cmd);
	int enabled = 0;

	*more = 0;
	switch (scmd->tags) {
	case MSG_SIMPLE_TAG:
		if (!device_blocked(stdev) &&
		    queue ? list_empty(&stdev->pending_cmds) : 1) {
			enabled = 1;
			*more = 1;
		}

		break;
	case MSG_ORDERED_TAG:
		if (!device_blocked(stdev) &&
		    !stdev->active_cmds &&
		    queue ? list_empty(&stdev->pending_cmds) : 1) {
			enabled = 1;
			stdev->state |= 1 << STDEV_ORDERED;
		}
		break;
	case MSG_HEAD_TAG:
		BUG_ON(!queue);
		stdev->state |= 1 << STDEV_HEAD;
		enabled = 1;
		break;
	default:
		printk("unknown scsi tag %x\n", scmd->tags);
		enabled = 1;
		*more = 1;
		break;
	}

	return enabled;
}

static void device_queue_cmd(void *data)
{
	struct tgt_cmd *cmd = data;
	cmd->device->dt->execute_cmd(cmd);
}

static void scsi_tgt_execute_pending_cmds(struct tgt_device *device)
{
	struct scsi_tgt_device *stdev = device->pt_data;
	struct tgt_cmd *cmd, *tmp;
	struct scsi_tgt_cmd *scmd;
	int enabled, more;

	list_for_each_entry_safe(cmd, tmp, &stdev->pending_cmds, clist) {
		scmd = tgt_cmd_to_scsi(cmd);

		enabled = scsi_tgt_task_state(cmd, 0, &more);
		BUG_ON(!enabled && more);

		if (enabled) {
			list_del(&cmd->clist);
			stdev->active_cmds++;
			INIT_WORK(&cmd->work, device_queue_cmd, cmd);
			queue_work(cmd->session->target->twq, &cmd->work);
		}

		if (!more)
			break;
	}
}

static void scsi_tgt_complete_cmd(struct tgt_cmd *cmd)
{
	struct scsi_tgt_cmd *scmd = tgt_cmd_to_scsi(cmd);
	struct tgt_device *device = cmd->device;
	struct scsi_tgt_device *stdev = device->pt_data;
	unsigned long flags;

	spin_lock_irqsave(&stdev->lock, flags);

	stdev->active_cmds--;

	switch (scmd->tags) {
	case MSG_SIMPLE_TAG:
		break;
	case MSG_ORDERED_TAG:
		stdev->state &= ~(1 << STDEV_ORDERED);
		break;
	case MSG_HEAD_TAG:
		stdev->state &= ~(1 << STDEV_HEAD);
		break;
	default:
		break;
	}

	if (!list_empty(&stdev->pending_cmds))
		scsi_tgt_execute_pending_cmds(device);

	spin_unlock_irqrestore(&stdev->lock, flags);
}

static int scsi_tgt_execute_cmd(struct tgt_cmd *cmd)
{
	struct tgt_device *device = cmd->device;
	struct scsi_tgt_device *stdev = device->pt_data;
	unsigned long flags;
	int err, enabled, more;

	BUG_ON(!device);

	spin_lock_irqsave(&stdev->lock, flags);

	/* Do we need our own list_head? */
	BUG_ON(!list_empty(&cmd->clist));

	enabled = scsi_tgt_task_state(cmd, 1, &more);
	if (enabled)
		stdev->active_cmds++;
	else
		list_add_tail(&cmd->clist, &stdev->pending_cmds);

	spin_unlock_irqrestore(&stdev->lock, flags);

	if (enabled)
		err = device->dt->execute_cmd(cmd);
	else
		err = TGT_CMD_KERN_QUEUED;

	return err;
}

static void scsi_tgt_build_uspace_pdu(struct tgt_cmd *cmd, void *data)
{
	struct scsi_tgt_cmd *scmd = (struct scsi_tgt_cmd *)cmd->proto_priv;
	memcpy(data, scmd->scb, sizeof(scmd->scb));
}

static void scsi_tgt_attach_device(void *data)
{
	struct scsi_tgt_device *stdev = data;

	spin_lock_init(&stdev->lock);
	INIT_LIST_HEAD(&stdev->pending_cmds);
	stdev->active_cmds = 0;
}

static void scsi_tgt_detach_device(void *data)
{
	struct scsi_tgt_device *stdev = data;

	/* TODO */
	BUG_ON(!list_empty(&stdev->pending_cmds));
}

static struct tgt_protocol scsi_tgt_proto = {
	.name = "scsi",
	.module = THIS_MODULE,
	.create_cmd = scsi_tgt_create_cmd,
	.build_uspace_pdu = scsi_tgt_build_uspace_pdu,
	.execute_cmd = scsi_tgt_execute_cmd,
	.complete_cmd = scsi_tgt_complete_cmd,
	.attach_device = scsi_tgt_attach_device,
	.detach_device = scsi_tgt_detach_device,
	.priv_dev_data_size = sizeof(struct scsi_tgt_device),
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
