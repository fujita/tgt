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

enum {
	TGT_SCSI_QUEUE_BLOCKED = TGT_QUEUE_PRIVATE_START,
};

static struct request *elevator_tgt_scsi_next_request(request_queue_t *q)
{
	struct request *rq;
	struct scsi_tgt_cmd *scmd;
	int enabled = 0;
	struct tgt_queuedata *tqd = tgt_qdata(q);

	if (list_empty(&q->queue_head))
		return NULL;

	rq = list_entry_rq(q->queue_head.next);

	scmd = tgt_cmd_to_scsi(rq->special);
	dprintk("%p %x %x %llx %d\n", rq->special, scmd->tags, scmd->scb[0],
		(unsigned long long) tqd->qflags, tqd->active_cmd);
	switch (scmd->tags) {
	case MSG_SIMPLE_TAG:
		if (!test_bit(TGT_SCSI_QUEUE_BLOCKED, &tqd->qflags))
			enabled = 1;
	case MSG_ORDERED_TAG:
		if (!test_bit(TGT_SCSI_QUEUE_BLOCKED, &tqd->qflags) &&
		    !tqd->active_cmd)
			enabled = 1;
		break;
	case MSG_HEAD_TAG:
		enabled = 1;
		break;
	default:
		BUG();
	}

	return enabled ? rq : NULL;
}

static void elevator_tgt_scsi_add_request(request_queue_t *q,
					  struct request *rq, int where)
{
	struct scsi_tgt_cmd *scmd = tgt_cmd_to_scsi(rq->special);

	switch (scmd->tags) {
	case MSG_SIMPLE_TAG:
	case MSG_ORDERED_TAG:
		list_add_tail(&rq->queuelist, &q->queue_head);
		break;
	case MSG_HEAD_TAG:
		list_add(&rq->queuelist, &q->queue_head);
		break;
	default:
		eprintk("unknown scsi tag %p %x %x\n",
			rq->special, scmd->tags, scmd->scb[0]);

		scmd->tags = MSG_SIMPLE_TAG;
		list_add_tail(&rq->queuelist, &q->queue_head);
	}
}

static void elevator_tgt_scsi_remove_request(request_queue_t *q,
					     struct request *rq)
{
	struct tgt_queuedata *tqd = tgt_qdata(q);
	struct tgt_cmd *cmd = rq->special;
	struct scsi_tgt_cmd *scmd = tgt_cmd_to_scsi(cmd);

	tqd->active_cmd++;

	dprintk("%p %x %x %llx %d %llu\n", rq->special, scmd->tags, scmd->scb[0],
		(unsigned long long) tqd->qflags, tqd->active_cmd,
		cmd->device ? cmd->device->dev_id : ~0ULL);

	if (scmd->tags == MSG_ORDERED_TAG || scmd->tags == MSG_HEAD_TAG)
		set_bit(TGT_SCSI_QUEUE_BLOCKED, &tqd->qflags);
}

static struct elevator_type elevator_tgt_scsi = {
	.ops = {
		.elevator_next_req_fn = elevator_tgt_scsi_next_request,
		.elevator_add_req_fn = elevator_tgt_scsi_add_request,
		.elevator_remove_req_fn = elevator_tgt_scsi_remove_request,
	},
	.elevator_name = __stringify(KBUILD_MODNAME),
	.elevator_owner = THIS_MODULE,
};

static void scsi_tgt_complete_cmd(struct tgt_cmd *cmd)
{
	struct request_queue *q = cmd->rq->q;
	struct tgt_queuedata *tqd = tgt_qdata(q);
	struct scsi_tgt_cmd *scmd = tgt_cmd_to_scsi(cmd);
	unsigned long flags;

	dprintk("%p %x %x %llx %d %llu\n", cmd, scmd->tags, scmd->scb[0],
		(unsigned long long) tqd->qflags, tqd->active_cmd,
		cmd->device ? cmd->device->dev_id : ~0ULL);

	spin_lock_irqsave(q->queue_lock, flags);
	tqd->active_cmd--;
	if (scmd->tags == MSG_ORDERED_TAG || scmd->tags == MSG_HEAD_TAG)
		clear_bit(TGT_SCSI_QUEUE_BLOCKED, &tqd->qflags);
	blk_plug_device(q);
	spin_unlock_irqrestore(q->queue_lock, flags);

	if (cmd->device)
		tgt_device_put(cmd->device);
}

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
		eprintk("Could not allocate command\n");
		return NULL;
	}
	scmd = tgt_cmd_to_scsi(cmd);
	memcpy(scmd->scb, scb, sizeof(scmd->scb));
	scmd->tags = tags;

	/* translate target driver LUN to device id */
	cmd->dev_id = scsi_tgt_translate_lun(lun, lun_size);
	cmd->device = device = tgt_device_get(session->target, cmd->dev_id);

	/* is this device specific */
	cmd->data_dir = data_dir;
	/*
	 * set bufflen based on data_len for now, but let device specific
	 * handler overide just in case
	 */
	cmd->bufflen = data_len;
	/* do scsi device specific setup */
	if (device)
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

static void __tgt_uspace_cmd_send(void *data)
{
	struct tgt_cmd *cmd = data;
	int err;

	err = tgt_uspace_cmd_send(cmd, GFP_KERNEL);
	if (err >= 0)
		return;

	scsi_tgt_sense_data_build(cmd, HARDWARE_ERROR, 0, 0);
	tgt_transfer_response(cmd);
}

static int scsi_tgt_execute_cmd(struct tgt_cmd *cmd)
{
	dprintk("%p %x\n", cmd, tgt_cmd_to_scsi(cmd)->scb[0]);

	if (!cmd->device) {
		INIT_WORK(&cmd->work, __tgt_uspace_cmd_send, cmd);
		queue_work(cmd->session->target->twq, &cmd->work);
		return TGT_CMD_KERN_QUEUED;
	} else
		return cmd->device->dt->execute_cmd(cmd);
}

static void scsi_tgt_uspace_pdu_build(struct tgt_cmd *cmd, void *data)
{
	struct scsi_tgt_cmd *scmd = (struct scsi_tgt_cmd *)cmd->proto_priv;
	memcpy(data, scmd->scb, sizeof(scmd->scb));
}

static void scsi_tgt_uspace_cmd_complete(struct tgt_cmd *cmd)
{
	/* userspace did everything for us just copy the buffer */
	if (cmd->result != SAM_STAT_GOOD)
		scsi_tgt_sense_copy(cmd);
}

static struct tgt_protocol scsi_tgt_proto = {
	.name = "scsi",
	.module = THIS_MODULE,
	.elevator = elevator_tgt_scsi.elevator_name,
	.create_cmd = scsi_tgt_create_cmd,
	.uspace_pdu_build = scsi_tgt_uspace_pdu_build,
	.uspace_cmd_complete = scsi_tgt_uspace_cmd_complete,
	.execute_cmd = scsi_tgt_execute_cmd,
	.complete_cmd = scsi_tgt_complete_cmd,
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
		goto protocol_unregister;

	err = elv_register(&elevator_tgt_scsi);
	if (err)
		goto cache_destroy;

	return 0;
cache_destroy:
	kmem_cache_destroy(scsi_tgt_cmd_cache);
protocol_unregister:
	tgt_protocol_unregister(&scsi_tgt_proto);

	return err;
}

static void __exit scsi_tgt_exit(void)
{
	elv_unregister(&elevator_tgt_scsi);
	kmem_cache_destroy(scsi_tgt_cmd_cache);
	tgt_protocol_unregister(&scsi_tgt_proto);
}

module_init(scsi_tgt_init);
module_exit(scsi_tgt_exit);
MODULE_LICENSE("GPL");
