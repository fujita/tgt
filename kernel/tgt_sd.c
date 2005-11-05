/*
 * scsi disk functions
 *
 * (C) 2005 FUJITA Tomonori <tomof@acm.org>
 * (C) 2005 Mike Christie <michaelc@cs.wisc.edu>
 * This code is licenced under the GPL.
 */

#include <linux/types.h>
#include <linux/blkdev.h>
#include <linux/uio.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/writeback.h>

#include <scsi/scsi.h>

#include <tgt.h>
#include <tgt_device.h>
#include <tgt_scsi.h>

/*
 * TODO set per device segment, max_sectors, etc limits
 */
static int tgt_sd_create(struct tgt_device *device)
{
	struct inode *inode;

	inode = device->file->f_dentry->d_inode;
	if (S_ISREG(inode->i_mode))
		;
	else if (S_ISBLK(inode->i_mode))
		inode = inode->i_bdev->bd_inode;
	else
		/*
		 * can we handle scsi tape too actually?
		 */
		return -EINVAL;

	device->size = inode->i_size;
	printk("%d %llu\n", device->fd, inode->i_size >> 9);

	return 0;
}

static void tgt_sd_prep(struct tgt_cmd *cmd, uint32_t data_len)
{
	struct scsi_tgt_cmd *scmd = tgt_cmd_to_scsi(cmd);
	uint8_t *scb = scmd->scb;
	uint64_t off = 0;

	/*
	 * set offset
	 */
	switch (scb[0]) {
	case READ_6:
	case WRITE_6:
		off = ((scb[1] & 0x1f) << 16) + (scb[2] << 8) + scb[3];
		break;
	case READ_10:
	case WRITE_10:
	case WRITE_VERIFY:
		off = be32_to_cpu(*(uint32_t *) &scb[2]);
		break;
	case READ_16:
	case WRITE_16:
		off = be64_to_cpu(*(uint64_t *) &scb[2]);
		break;
	default:
		break;
	}

	off <<= 9;

	/*
	 * we trust the data_len passed in for now
	 */
	cmd->bufflen = data_len;
	cmd->offset = off;
}

static void tgt_sd_end_rq(struct request *rq)
{
	struct tgt_cmd *cmd = rq->end_io_data;
	struct scsi_tgt_cmd *scmd = tgt_cmd_to_scsi(cmd);

	if (rq->sense_len) {
		memcpy(scmd->sense_buff, rq->sense, SCSI_SENSE_BUFFERSIZE);
		cmd->result = SAM_STAT_CHECK_CONDITION;
	} else if (rq->errors) {
		/*
		 * TODO check *_byte and just send error upwards
		 */
		scsi_tgt_sense_data_build(cmd, HARDWARE_ERROR, 0, 0);
		cmd->result = SAM_STAT_CHECK_CONDITION;
	} else
		cmd->result = SAM_STAT_GOOD;

	tgt_transfer_response(cmd);
	__blk_put_request(rq->q, rq);
}

/*
 * this is going to the bio layer
 */
static struct bio *bio_map_pages(request_queue_t *q, struct page *page,
				 unsigned int len, unsigned int offset,
				 unsigned int gfp_mask)
{
	int nr_pages = (len + PAGE_SIZE - 1) >> PAGE_SHIFT;
	struct bio *bio;

	bio = bio_alloc(gfp_mask, nr_pages);
	if (!bio)
		return ERR_PTR(-ENOMEM);

	while (len) {
		unsigned int bytes = PAGE_SIZE - offset;

		if (bytes > len)
			bytes = len;

		if (__bio_add_page(q, bio, page, bytes, offset) < bytes)
			goto free_bio;

		offset = 0;
		len -= bytes;
		page++;
	}

	return bio;

 free_bio:
	bio_put(bio);
	return ERR_PTR(-EINVAL);
}

/*
 * this is going to scsi-ml or the block layer
 */
static int req_map_sg(request_queue_t *q, struct request *rq,
		      struct scatterlist *sg, int nsegs, unsigned int gfp)
{
	struct bio *bio;
	int i, err = 0;
	unsigned int len = 0;

	for (i = 0; i < nsegs; i++) {
		bio = bio_map_pages(q, sg[i].page, sg[i].length, sg[i].offset,
				    gfp);
		if (IS_ERR(bio)) {
			err = PTR_ERR(bio);
			goto free_bios;
		}
		len += sg[i].length;

		bio->bi_flags &= ~(1 << BIO_SEG_VALID);
		if (rq_data_dir(rq) == WRITE)
			bio->bi_rw |= (1 << BIO_RW);
		blk_queue_bounce(q, &bio);

		if (i == 0)
			blk_rq_bio_prep(q, rq, bio);
		else if (!q->back_merge_fn(q, rq, bio)) {
			bio_endio(bio, bio->bi_size, 0);
			err = -EINVAL;
			goto free_bios;
		} else {
			rq->biotail->bi_next = bio;
			rq->biotail = bio;
			rq->hard_nr_sectors += bio_sectors(bio);
			rq->nr_sectors = rq->hard_nr_sectors;
		}
	}

	rq->buffer = rq->data = NULL;
	rq->data_len = len;
	return 0;

 free_bios:
	while ((bio = rq->bio) != NULL) {
		rq->bio = bio->bi_next;
		/*
		 * call endio instead of bio_put incase it was bounced
		 */
		bio_endio(bio, bio->bi_size, 0);
	}

	return err;
}

/*
 * TODO part of this will move to a io_handler callout
 */
static int tgt_sd_execute_rq(struct tgt_cmd *cmd)
{
	struct scsi_tgt_cmd *scmd = tgt_cmd_to_scsi(cmd);
	struct file *file = cmd->device->file;
	request_queue_t *q = bdev_get_queue(file->f_dentry->d_inode->i_bdev);
	struct request *rq;
	int write = (cmd->data_dir == DMA_TO_DEVICE);

	rq = blk_get_request(q, write, GFP_KERNEL | __GFP_NOFAIL);
	if (!rq)
		goto hw_error;

	if (req_map_sg(q, rq, cmd->sg, cmd->sg_count,
			GFP_KERNEL | __GFP_NOFAIL))
		goto free_request;

	rq->cmd_len = COMMAND_SIZE(scmd->scb[0]);
	memcpy(rq->cmd, scmd->scb, rq->cmd_len);
	rq->sense_len = 0;
	rq->sense = scmd->sense_buff;
	rq->end_io_data = cmd;
	rq->timeout = 60 * HZ; /* TODO */
	rq->flags |= REQ_BLOCK_PC;

	blk_execute_rq_nowait(q, NULL, rq, 0, tgt_sd_end_rq);
	return 0;

 free_request:
	blk_put_request(rq);
 hw_error:
	scsi_tgt_sense_data_build(cmd, HARDWARE_ERROR, 0, 0);
	return -ENOMEM;
}

static int tgt_sd_execute(struct tgt_cmd *cmd)
{
	struct tgt_device *device = cmd->device;
	loff_t pos = cmd->offset;

	if (cmd->bufflen + pos > device->size) {
		scsi_tgt_sense_data_build(cmd, HARDWARE_ERROR, 0, 0);
		return TGT_CMD_FAILED;
	}
	/*
	 * TODO this will become device->io_handler->queue_cmd
	 * when we seperate the io_handlers
	 */
	return tgt_sd_execute_rq(cmd) ? TGT_CMD_FAILED : TGT_CMD_KERN_QUEUED;
}

static struct tgt_device_template tgt_sd = {
	.name = "tgt_sd",
	.module = THIS_MODULE,
	.create = tgt_sd_create,
	.execute_cmd = tgt_sd_execute,
	.prep_cmd = tgt_sd_prep,
};

static int __init tgt_sd_init(void)
{
	return tgt_device_template_register(&tgt_sd);
}

static void __exit tgt_sd_exit(void)
{
	tgt_device_template_unregister(&tgt_sd);
}

module_init(tgt_sd_init);
module_exit(tgt_sd_exit);
MODULE_LICENSE("GPL");
