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
#include <tgt_target.h>
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

	device->use_clustering = 1;
	device->size = inode->i_size;
	dprintk("%d %llu\n", device->fd, inode->i_size >> 9);

	return 0;
}

/*
 * is this device specific or common? Should it be moved to the protocol.
 */
static void tgt_vsd_prep(struct tgt_cmd *cmd)
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

	cmd->offset = off;
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
static int vsd_execute_file_io(struct tgt_cmd *cmd, int op)
{
	struct file *file = cmd->device->file;
	ssize_t ret;
	struct iovec *iov;
	loff_t pos = cmd->offset;

	iov = sg_to_iovec(cmd->sg, cmd->sg_count);
	if (!iov)
		return -ENOMEM;

	if (op == READ)
		ret = generic_file_readv(file, iov, cmd->sg_count, &pos);
	else
		ret = generic_file_writev(file, iov, cmd->sg_count, &pos);

	kfree(iov);

	if (ret < 0 || ret != cmd->bufflen) {
		eprintk("I/O error %d %Zd %u %lld %" PRIu64 "\n",
			op, ret, cmd->bufflen, pos, cmd->device->size);
		return -EINVAL;
	}

	/* sync_page_range(inode, inode->i_mapping, pos, (size_t) cmd->bufflen); */
	return 0;
}

static void __tgt_vsd_execute(void *data)
{
	struct tgt_cmd *cmd = data;
	struct scsi_tgt_cmd *scmd = tgt_cmd_to_scsi(cmd);
	int err, rw;

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
		err = tgt_uspace_cmd_send(cmd, GFP_KERNEL);
		/*
		 * successfully queued
		 */
		if (err >= 0)
			return;

		goto failed;
	};

	err = vsd_execute_file_io(cmd, rw);
	if (!err) {
		cmd->result = SAM_STAT_GOOD;
		goto done;
	}

	/*
	 * we should do a switch but I am not sure of all the err values
	 * returned. If you find one add it
	 */
failed:
	/* TODO if -ENOMEM return QUEUEFULL or BUSY ??? */
	scsi_tgt_sense_data_build(cmd, HARDWARE_ERROR, 0, 0);
done:
	tgt_transfer_response(cmd);
}

static int tgt_vsd_execute(struct tgt_cmd *cmd)
{
	/*
	 * TODO: this module needs to do async non blocking io or create
	 * its own threads
	 */
	INIT_WORK(&cmd->work, __tgt_vsd_execute, cmd);
	queue_work(cmd->session->target->twq, &cmd->work);
	return TGT_CMD_KERN_QUEUED;
}

static struct tgt_device_template tgt_vsd = {
	.name = "tgt_vsd",
	.module = THIS_MODULE,
	.create = tgt_vsd_create,
	.execute_cmd = tgt_vsd_execute,
	.prep_cmd = tgt_vsd_prep,
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
