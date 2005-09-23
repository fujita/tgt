/*
 * virtual scsi disk functions
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

static int tgt_vsd_create(struct tgt_device *device)
{
	struct inode *inode;

	inode = device->file->f_dentry->d_inode;
	if (S_ISREG(inode->i_mode))
		;
	else if (S_ISBLK(inode->i_mode))
		inode = inode->i_bdev->bd_inode;
	else
		return -EINVAL;

	device->size = inode->i_size;
	printk("%d %llu\n", device->fd, inode->i_size >> 9);

	return 0;
}

/*
 * is this device specific or common? Should it be moved to the protocol.
 */
static void tgt_vsd_prep(struct tgt_cmnd *cmnd, uint32_t data_len)
{
	struct scsi_tgt_cmnd *scmnd = tgt_cmnd_to_scsi(cmnd);
	uint8_t *scb = scmnd->scb;
	uint64_t off = 0;
/*	uint32_t len = 0; */

	/*
	 * set bufflen and offset
	 */
	switch (scb[0]) {
	case READ_6:
	case WRITE_6:
		off = ((scb[1] & 0x1f) << 16) + (scb[2] << 8) + scb[3];
/*		len = scb[4];
		if (!len)
			len = 256;*/
		break;
	case READ_10:
	case WRITE_10:
	case WRITE_VERIFY:
		off = be32_to_cpu(*(u32 *) &scb[2]);
/*		len = (scb[7] << 8) + scb[8]; */
		break;
	case READ_16:
	case WRITE_16:
		off = be64_to_cpu(*(u64 *)&scb[2]);
/*		len = be32_to_cpu(*(u32 *)&scb[10]); */
		break;
	default:
		break;
	}

	off <<= 9;
/*	len <<= 9; */

	/*
	 * we trust the data_len passed in for now
	 */
	cmnd->bufflen = data_len;
	cmnd->offset = off;
}

static void tgt_vsd_uspace_complete(struct tgt_cmnd *cmnd)
{
	/* userspace did everything for us just copy the buffer */
	if (cmnd->result != SAM_STAT_GOOD)
		scsi_tgt_sense_copy(cmnd);
}

/*
 * TODO: We need to redo our scatter lists so they take into account
 * this common usage, but also not violate HW limits
 */
static struct iovec* sg_to_iovec(struct scatterlist *sg, int sg_count)
{
	struct iovec* iov;
	int i;

	iov = kmalloc(sizeof(struct iovec) * sg_count, GFP_KERNEL);
	if (!iov)
		return NULL;

	for (i = 0; i < sg_count; i++) {
		iov[i].iov_base = page_address(sg[i].page) + sg[i].offset;
		iov[i].iov_len = sg[i].length;
	}

	return iov;
}

/*
 * TODO this will move to a io_handler callout
 */
static int vsd_queue_file_io(struct tgt_cmnd *cmnd, int op)
{
	struct file *file = cmnd->device->file;
	ssize_t size;
	struct iovec *iov;
	loff_t pos = cmnd->offset;

	iov = sg_to_iovec(cmnd->sg, cmnd->sg_count);
	if (!iov)
		return -ENOMEM;

	if (op == READ)
		size = generic_file_readv(file, iov, cmnd->sg_count, &pos);
	else
		size = generic_file_writev(file, iov, cmnd->sg_count, &pos);

	kfree(iov);

/* not yet used
	if (sync)
		err = sync_page_range(inode, inode->i_mapping, pos,
				      (size_t) cmnd->bufflen);
*/
	return size;
}

static int tgt_vsd_queue(struct tgt_cmnd *cmnd)
{
	struct scsi_tgt_cmnd *scmnd = tgt_cmnd_to_scsi(cmnd);
	struct tgt_device *device = cmnd->device;
	loff_t pos = cmnd->offset;
	int err = 0, rw;

	if (cmnd->bufflen + pos > device->size) {
		scsi_tgt_sense_data_build(cmnd, HARDWARE_ERROR, 0, 0);
		return TGT_CMND_FAILED;
	}

	switch (scmnd->scb[0]) {
	case READ_6:
	case READ_10:
	case READ_16:
		rw = READ;
		break;
	case WRITE_6:
	case WRITE_10:
	case WRITE_16:
	case WRITE_VERIFY:
		rw = WRITE;
		break;
	default:
		err = tgt_uspace_cmnd_send(cmnd);
		/*
		 * successfully queued
		 */
		if (err >= 0)
			return TGT_CMND_USPACE_QUEUED;

		scsi_tgt_sense_data_build(cmnd, HARDWARE_ERROR, 0, 0);
		return TGT_CMND_FAILED;
	};

	/*
	 * TODO this will become device->io_handler->queue_cmnd
	 * when we seperate the io_handlers
	 */
	err = vsd_queue_file_io(cmnd, rw);
	/*
	 * we should to a switch but I am not sure of all the err values
	 * returned. If you find one add it
	 */
	if (err != cmnd->bufflen) {
		scsi_tgt_sense_data_build(cmnd, HARDWARE_ERROR, 0, 0);
		return TGT_CMND_FAILED;
	} else {
		cmnd->result = SAM_STAT_GOOD;
		return TGT_CMND_COMPLETED;
	}
}

static struct tgt_device_template tgt_vsd = {
	.name = "tgt_vsd",
	.module = THIS_MODULE,
	.create = tgt_vsd_create,
	.queue_cmnd = tgt_vsd_queue,
	.prep_cmnd = tgt_vsd_prep,
	.complete_uspace_cmnd = tgt_vsd_uspace_complete,
};

static int __init tgt_vsd_init(void)
{
	return tgt_device_template_register(&tgt_vsd);
}

static void __exit tgt_vsd_exit(void)
{
	tgt_device_template_unregister(&tgt_vsd);
}

module_init(tgt_vsd_init);
module_exit(tgt_vsd_exit);
MODULE_LICENSE("GPL");
