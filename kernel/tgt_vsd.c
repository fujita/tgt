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
static void tgt_vsd_prep(struct tgt_cmd *cmd, uint32_t data_len)
{
	struct scsi_tgt_cmd *scmd = tgt_cmd_to_scsi(cmd);
	uint8_t *scb = scmd->scb;
	uint64_t off = 0;

	/*
	 * set bufflen and offset
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

static void tgt_vsd_uspace_complete(struct tgt_cmd *cmd)
{
	/* userspace did everything for us just copy the buffer */
	if (cmd->result != SAM_STAT_GOOD)
		scsi_tgt_sense_copy(cmd);
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
static int vsd_queue_file_io(struct tgt_cmd *cmd, int op)
{
	struct file *file = cmd->device->file;
	ssize_t size;
	struct iovec *iov;
	loff_t pos = cmd->offset;

	iov = sg_to_iovec(cmd->sg, cmd->sg_count);
	if (!iov)
		return -ENOMEM;

	if (op == READ)
		size = generic_file_readv(file, iov, cmd->sg_count, &pos);
	else
		size = generic_file_writev(file, iov, cmd->sg_count, &pos);

	kfree(iov);

/* not yet used
	if (sync)
		err = sync_page_range(inode, inode->i_mapping, pos,
				      (size_t) cmd->bufflen);
*/
	return size;
}

static int tgt_vsd_queue(struct tgt_cmd *cmd)
{
	struct scsi_tgt_cmd *scmd = tgt_cmd_to_scsi(cmd);
	struct tgt_device *device = cmd->device;
	loff_t pos = cmd->offset;
	int err = 0, rw;

	if (cmd->bufflen + pos > device->size) {
		scsi_tgt_sense_data_build(cmd, HARDWARE_ERROR, 0, 0);
		return TGT_CMD_FAILED;
	}

	switch (scmd->scb[0]) {
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
		err = tgt_uspace_cmd_send(cmd);
		/*
		 * successfully queued
		 */
		if (err >= 0)
			return TGT_CMD_USPACE_QUEUED;

		scsi_tgt_sense_data_build(cmd, HARDWARE_ERROR, 0, 0);
		return TGT_CMD_FAILED;
	};

	/*
	 * TODO this will become device->io_handler->queue_cmd
	 * when we seperate the io_handlers
	 */
	err = vsd_queue_file_io(cmd, rw);
	/*
	 * we should to a switch but I am not sure of all the err values
	 * returned. If you find one add it
	 */
	if (err != cmd->bufflen) {
		scsi_tgt_sense_data_build(cmd, HARDWARE_ERROR, 0, 0);
		return TGT_CMD_FAILED;
	} else {
		cmd->result = SAM_STAT_GOOD;
		return TGT_CMD_COMPLETED;
	}
}

static struct tgt_device_template tgt_vsd = {
	.name = "tgt_vsd",
	.module = THIS_MODULE,
	.create = tgt_vsd_create,
	.queue_cmd = tgt_vsd_queue,
	.prep_cmd = tgt_vsd_prep,
	.complete_uspace_cmd = tgt_vsd_uspace_complete,
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
