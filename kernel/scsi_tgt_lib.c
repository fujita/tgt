/*
 * SCSI target lib functions
 *
 * Copyright (C) 2005 Mike Christie <michaelc@cs.wisc.edu>
 * Copyright (C) 2005 FUJITA Tomonori <tomof@acm.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */
#include <linux/blkdev.h>
#include <linux/elevator.h>
#include <linux/module.h>
#include <linux/pagemap.h>
#include <scsi/scsi.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_tgt.h>
#include <../drivers/md/dm-bio-list.h>

#include "scsi_tgt_priv.h"

static struct workqueue_struct *scsi_tgtd;
static kmem_cache_t *scsi_tgt_cmd_cache;

/*
 * TODO: this struct will be killed when the block layer supports large bios
 * and James's work struct code is in
 */
struct scsi_tgt_cmd {
	/* TODO replace work with James b's code */
	struct work_struct work;
	/* TODO replace the lists with a large bio */
	struct bio_list xfer_done_list;
	struct bio_list xfer_list;
	struct scsi_lun *lun;
};

static void scsi_unmap_user_pages(struct scsi_tgt_cmd *tcmd)
{
	struct bio *bio;

	/* must call bio_endio in case bio was bounced */
	while ((bio = bio_list_pop(&tcmd->xfer_done_list))) {
		bio_endio(bio, bio->bi_size, 0);
		bio_unmap_user(bio);
	}

	while ((bio = bio_list_pop(&tcmd->xfer_list))) {
		bio_endio(bio, bio->bi_size, 0);
		bio_unmap_user(bio);
	}
}

static void scsi_tgt_cmd_destroy(void *data)
{
	struct scsi_cmnd *cmd = data;
	struct scsi_tgt_cmd *tcmd = cmd->request->end_io_data;

	dprintk("cmd %p %d %lu\n", cmd, cmd->sc_data_direction,
		rq_data_dir(cmd->request));
	/*
	 * We must set rq->flags here because bio_map_user and
	 * blk_rq_bio_prep ruined ti.
	 */
	if (cmd->sc_data_direction == DMA_TO_DEVICE)
		cmd->request->flags |= 1;
	else
		cmd->request->flags &= ~1UL;

	scsi_unmap_user_pages(tcmd);
	scsi_tgt_uspace_send_status(cmd, GFP_KERNEL);
	kmem_cache_free(scsi_tgt_cmd_cache, tcmd);
	scsi_host_put_command(scsi_tgt_cmd_to_host(cmd), cmd);
}

static void init_scsi_tgt_cmd(struct request *rq, struct scsi_tgt_cmd *tcmd)
{
	tcmd->lun = rq->end_io_data;
	bio_list_init(&tcmd->xfer_list);
	bio_list_init(&tcmd->xfer_done_list);
}

static int scsi_uspace_prep_fn(struct request_queue *q, struct request *rq)
{
	struct scsi_tgt_cmd *tcmd;

	tcmd = kmem_cache_alloc(scsi_tgt_cmd_cache, GFP_ATOMIC);
	if (!tcmd)
		return BLKPREP_DEFER;

	init_scsi_tgt_cmd(rq, tcmd);
	rq->end_io_data = tcmd;
	rq->flags |= REQ_DONTPREP;
	return BLKPREP_OK;
}

static void scsi_uspace_request_fn(struct request_queue *q)
{
	struct request *rq;
	struct scsi_cmnd *cmd;
	struct scsi_tgt_cmd *tcmd;

	/*
	 * TODO: just send everthing in the queue to userspace in
	 * one vector instead of multiple calls
	 */
	while ((rq = elv_next_request(q)) != NULL) {
		cmd = rq->special;
		tcmd = rq->end_io_data;

		/* the completion code kicks us in case we hit this */
		if (blk_queue_start_tag(q, rq))
			break;

		spin_unlock_irq(q->queue_lock);
		if (scsi_tgt_uspace_send(cmd, tcmd->lun, GFP_ATOMIC) < 0)
			goto requeue;
		spin_lock_irq(q->queue_lock);
	}

	return;
requeue:
	spin_lock_irq(q->queue_lock);
	/* need to track cnts and plug */
	blk_requeue_request(q, rq);
	spin_lock_irq(q->queue_lock);
}

/**
 * scsi_tgt_alloc_queue - setup queue used for message passing
 * shost: scsi host
 *
 * This should be called by the LLD after host allocation.
 * And will be released when the host is released.
 **/
int scsi_tgt_alloc_queue(struct Scsi_Host *shost)
{
	struct scsi_tgt_queuedata *queuedata;
	struct request_queue *q;
	int err;

	/*
	 * Do we need to send a netlink event or should uspace
	 * just respond to the hotplug event?
	 */
	q = __scsi_alloc_queue(shost, scsi_uspace_request_fn);
	if (!q)
		return -ENOMEM;

	queuedata = kzalloc(sizeof(*queuedata), GFP_KERNEL);
	if (!queuedata) {
		err = -ENOMEM;
		goto cleanup_queue;
	}
	queuedata->shost = shost;
	q->queuedata = queuedata;

	elevator_exit(q->elevator);
	err = elevator_init(q, "noop");
	if (err)
		goto free_data;

	blk_queue_prep_rq(q, scsi_uspace_prep_fn);
	/*
	 * this is a silly hack. We should probably just queue as many
	 * command as is recvd to userspace. uspace can then make
	 * sure we do not overload the HBA
	 */
	q->nr_requests = shost->hostt->can_queue;
	blk_queue_init_tags(q, shost->hostt->can_queue, NULL);
	/*
	 * We currently only support software LLDs so this does
	 * not matter for now. Do we need this for the cards we support?
	 * If so we should make it a host template value.
	 */
	blk_queue_dma_alignment(q, 0);
	shost->uspace_req_q = q;

	return 0;

free_data:
	kfree(queuedata);
cleanup_queue:
	blk_cleanup_queue(q);
	return err;
}
EXPORT_SYMBOL_GPL(scsi_tgt_alloc_queue);

struct Scsi_Host *scsi_tgt_cmd_to_host(struct scsi_cmnd *cmd)
{
	struct scsi_tgt_queuedata *queue = cmd->request->q->queuedata;
	return queue->shost;
}
EXPORT_SYMBOL_GPL(scsi_tgt_cmd_to_host);

/**
 * scsi_tgt_queue_command - queue command for userspace processing
 * @cmd:	scsi command
 * @scsilun:	scsi lun
 * @noblock:	set to nonzero if the command should be queued
 **/
void scsi_tgt_queue_command(struct scsi_cmnd *cmd, struct scsi_lun *scsilun,
			    int noblock)
{
	/*
	 * For now this just calls the request_fn from this context.
	 * For HW llds though we do not want to execute from here so
	 * the elevator code needs something like a REQ_TGT_CMD or
	 * REQ_MSG_DONT_UNPLUG_IMMED_BECUASE_WE_WILL_HANDLE_IT
	 */
	cmd->request->end_io_data = scsilun;
	elv_add_request(cmd->request->q, cmd->request, ELEVATOR_INSERT_BACK, 1);
}
EXPORT_SYMBOL_GPL(scsi_tgt_queue_command);

/*
 * This is run from a interrpt handler normally and the unmap
 * needs process context so we must queue
 */
static void scsi_tgt_cmd_done(struct scsi_cmnd *cmd)
{
	struct scsi_tgt_cmd *tcmd = cmd->request->end_io_data;

	dprintk("cmd %p %lu\n", cmd, rq_data_dir(cmd->request));

	/* don't we have to call this if result is set or not */
	if (cmd->result) {
		scsi_tgt_uspace_send_status(cmd, GFP_ATOMIC);
		return;
	}

	INIT_WORK(&tcmd->work, scsi_tgt_cmd_destroy, cmd);
	queue_work(scsi_tgtd, &tcmd->work);
}

static int __scsi_tgt_transfer_response(struct scsi_cmnd *cmd)
{
	struct Scsi_Host *shost = scsi_tgt_cmd_to_host(cmd);
	int err;

	dprintk("cmd %p %lu\n", cmd, rq_data_dir(cmd->request));

	err = shost->hostt->transfer_response(cmd, scsi_tgt_cmd_done);
	switch (err) {
	case SCSI_MLQUEUE_HOST_BUSY:
	case SCSI_MLQUEUE_DEVICE_BUSY:
		return -EAGAIN;
	}

	return 0;
}

static void scsi_tgt_transfer_response(struct scsi_cmnd *cmd)
{
	int err;

	err = __scsi_tgt_transfer_response(cmd);
	if (!err)
		return;

	cmd->result = DID_BUS_BUSY << 16;
	if (scsi_tgt_uspace_send_status(cmd, GFP_ATOMIC) <= 0)
		/* the eh will have to pick this up */
		printk(KERN_ERR "Could not send cmd %p status\n", cmd);
}

static int scsi_tgt_init_cmd(struct scsi_cmnd *cmd, gfp_t gfp_mask)
{
	struct request *rq = cmd->request;
	int count;

	cmd->use_sg = rq->nr_phys_segments;
	cmd->request_buffer = scsi_alloc_sgtable(cmd, gfp_mask);
	if (!cmd->request_buffer)
		return -ENOMEM;

	cmd->request_bufflen = rq->data_len;

	dprintk("cmd %p addr %p cnt %d %lu\n", cmd, cmd->buffer, cmd->use_sg,
		rq_data_dir(rq));
	count = blk_rq_map_sg(rq->q, rq, cmd->request_buffer);
	if (likely(count <= cmd->use_sg)) {
		cmd->use_sg = count;
		return 0;
	}

	eprintk("cmd %p addr %p cnt %d\n", cmd, cmd->buffer, cmd->use_sg);
	scsi_free_sgtable(cmd->request_buffer, cmd->sglist_len);
	return -EINVAL;
}

/* TODO: test this crap and replace bio_map_user with new interface maybe */
static int scsi_map_user_pages(struct scsi_tgt_cmd *tcmd, struct scsi_cmnd *cmd,
			       int rw)
{
	struct request_queue *q = cmd->request->q;
	struct request *rq = cmd->request;
	void *uaddr = cmd->buffer;
	unsigned int len = cmd->bufflen;
	struct bio *bio;
	int err;

	while (len > 0) {
		dprintk("%lx %u\n", (unsigned long) uaddr, len);
		bio = bio_map_user(q, NULL, (unsigned long) uaddr, len, rw, 1);
		if (IS_ERR(bio)) {
			err = PTR_ERR(bio);
			dprintk("fail to map %lx %u %d %x\n",
				(unsigned long) uaddr, len, err, cmd->cmnd[0]);
			goto unmap_bios;
		}

		uaddr += bio->bi_size;
		len -= bio->bi_size;

		/*
		 * The first bio is added and merged. We could probably
		 * try to add others using scsi_merge_bio() but for now
		 * we keep it simple. The first bio should be pretty large
		 * (either hitting the 1 MB bio pages limit or a queue limit)
		 * already but for really large IO we may want to try and
		 * merge these.
		 */
		if (!rq->bio) {
			blk_rq_bio_prep(q, rq, bio);
			rq->data_len = bio->bi_size;
		} else
			/* put list of bios to transfer in next go around */
			bio_list_add(&tcmd->xfer_list, bio);
	}

	cmd->offset = 0;
	err = scsi_tgt_init_cmd(cmd, GFP_KERNEL);
	if (err)
		goto unmap_bios;

	return 0;

unmap_bios:
	if (rq->bio) {
		bio_unmap_user(rq->bio);
		while ((bio = bio_list_pop(&tcmd->xfer_list)))
			bio_unmap_user(bio);
	}

	return err;
}

static int scsi_tgt_transfer_data(struct scsi_cmnd *);

static void scsi_tgt_data_transfer_done(struct scsi_cmnd *cmd)
{
	struct scsi_tgt_cmd *tcmd = cmd->request->end_io_data;
	struct bio *bio;
	int err;

	/* should we free resources here on error ? */
	if (cmd->result) {
send_uspace_err:
		if (scsi_tgt_uspace_send_status(cmd, GFP_ATOMIC) <= 0)
			/* the tgt uspace eh will have to pick this up */
			printk(KERN_ERR "Could not send cmd %p status\n", cmd);
		return;
	}

	dprintk("cmd %p request_bufflen %u bufflen %u\n",
		cmd, cmd->request_bufflen, cmd->bufflen);

	scsi_free_sgtable(cmd->request_buffer, cmd->sglist_len);
	bio_list_add(&tcmd->xfer_done_list, cmd->request->bio);

	cmd->buffer += cmd->request_bufflen;
	cmd->offset += cmd->request_bufflen;

	if (!tcmd->xfer_list.head) {
		scsi_tgt_transfer_response(cmd);
		return;
	}

	dprintk("cmd2 %p request_bufflen %u bufflen %u\n",
		cmd, cmd->request_bufflen, cmd->bufflen);

	bio = bio_list_pop(&tcmd->xfer_list);
	BUG_ON(!bio);

	blk_rq_bio_prep(cmd->request->q, cmd->request, bio);
	cmd->request->data_len = bio->bi_size;
	err = scsi_tgt_init_cmd(cmd, GFP_ATOMIC);
	if (err) {
		cmd->result = DID_ERROR << 16;
		goto send_uspace_err;
	}

	if (scsi_tgt_transfer_data(cmd)) {
		cmd->result = DID_NO_CONNECT << 16;
		goto send_uspace_err;
	}
}

static int scsi_tgt_transfer_data(struct scsi_cmnd *cmd)
{
	int err;
	struct Scsi_Host *host = scsi_tgt_cmd_to_host(cmd);

	err = host->hostt->transfer_data(cmd, scsi_tgt_data_transfer_done);
	switch (err) {
		case SCSI_MLQUEUE_HOST_BUSY:
		case SCSI_MLQUEUE_DEVICE_BUSY:
			return -EAGAIN;
	default:
		return 0;
	}
}

static int scsi_tgt_copy_sense(struct scsi_cmnd *cmd, unsigned long uaddr,
				unsigned len)
{
	char __user *p = (char __user *) uaddr;

	if (copy_from_user(cmd->sense_buffer, p,
			   min_t(unsigned, SCSI_SENSE_BUFFERSIZE, len))) {
		printk(KERN_ERR "Could not copy the sense buffer\n");
		return -EIO;
	}
	return 0;
}

int scsi_tgt_kspace_exec(int host_no, u32 cid, int result, u32 len, u64 offset,
			 unsigned long uaddr, u8 rw, u8 try_map)
{
	struct Scsi_Host *shost;
	struct scsi_cmnd *cmd;
	struct request *rq;
	int err = 0;

	dprintk("%d %u %d %u %llu %lx %u %u\n", host_no, cid, result,
		len, (unsigned long long) offset, uaddr, rw, try_map);

	/* TODO: replace with a O(1) alg */
	shost = scsi_host_lookup(host_no);
	if (IS_ERR(shost)) {
		printk(KERN_ERR "Could not find host no %d\n", host_no);
		return -EINVAL;
	}

	rq = blk_queue_find_tag(shost->uspace_req_q, cid);
	if (!rq) {
		printk(KERN_ERR "Could not find cid %u\n", cid);
		err = -EINVAL;
		goto done;
	}
	cmd = rq->special;

	dprintk("cmd %p result %d len %d bufflen %u %lu %x\n", cmd,
		result, len, cmd->request_bufflen, rq_data_dir(rq), cmd->cmnd[0]);

	/*
	 * store the userspace values here, the working values are
	 * in the request_* values
	 */
	cmd->buffer = (void *)uaddr;
	if (len)
		cmd->bufflen = len;
	cmd->result = result;

	if (!cmd->bufflen) {
		err = __scsi_tgt_transfer_response(cmd);
		goto done;
	}

	/*
	 * TODO: Do we need to handle case where request does not
	 * align with LLD.
	 */
	err = scsi_map_user_pages(rq->end_io_data, cmd, rw);
	if (err) {
		eprintk("%p %d\n", cmd, err);
		err = -EAGAIN;
		goto done;
	}

	/* userspace failure */
	if (cmd->result) {
		if (status_byte(cmd->result) == CHECK_CONDITION)
			scsi_tgt_copy_sense(cmd, uaddr, len);
		err = __scsi_tgt_transfer_response(cmd);
		goto done;
	}
	/* ask the target LLD to transfer the data to the buffer */
	err = scsi_tgt_transfer_data(cmd);

done:
	scsi_host_put(shost);
	return err;
}

static int __init scsi_tgt_init(void)
{
	int err;

	scsi_tgt_cmd_cache = kmem_cache_create("scsi_tgt_cmd",
					       sizeof(struct scsi_tgt_cmd),
					       0, 0, NULL, NULL);
	if (!scsi_tgt_cmd_cache)
		return -ENOMEM;

	scsi_tgtd = create_workqueue("scsi_tgtd");
	if (!scsi_tgtd) {
		err = -ENOMEM;
		goto free_kmemcache;
	}

	err = scsi_tgt_if_init();
	if (err)
		goto destroy_wq;

	return 0;

destroy_wq:
	destroy_workqueue(scsi_tgtd);
free_kmemcache:
	kmem_cache_destroy(scsi_tgt_cmd_cache);
	return err;
}

static void __exit scsi_tgt_exit(void)
{
	destroy_workqueue(scsi_tgtd);
	scsi_tgt_if_exit();
	kmem_cache_destroy(scsi_tgt_cmd_cache);
}

module_init(scsi_tgt_init);
module_exit(scsi_tgt_exit);

MODULE_DESCRIPTION("SCSI target core");
MODULE_LICENSE("GPL");
