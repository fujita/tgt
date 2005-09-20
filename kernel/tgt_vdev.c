/*
 * Target virtual device functions
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

#include <tgt.h>
#include <tgt_device.h>

struct tgt_vdev {
	struct file *filp;
};

static void tgt_vdev_destroy(struct tgt_device *device)
{
	struct tgt_vdev *vdev = device->dt_data;
	fput(vdev->filp);
}

static int open_file(struct tgt_vdev *vdev, int fd)
{
	struct file *filp;

	filp = fget(fd);
	if (!filp) {
		printk("Could not get fd %d\n", fd);
		return -EINVAL;
	}

	vdev->filp = filp;
	return 0;
}

static int tgt_vdev_create(struct tgt_device *device)
{
	struct tgt_vdev *vdev = device->dt_data;
	struct inode *inode;
	int err;

	err = open_file(vdev, device->fd);
	if (err)
		return err;

	inode = vdev->filp->f_dentry->d_inode;
	if (S_ISREG(inode->i_mode))
		;
	else if (S_ISBLK(inode->i_mode))
		inode = inode->i_bdev->bd_inode;
	else {
		err = -EINVAL;
		goto out;
	}

	device->size = inode->i_size;
	printk("%d %llu\n", device->fd, inode->i_size >> 9);

	return 0;
out:
	fput(vdev->filp);
	return err;
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

static int tgt_vdev_queue(struct tgt_device *device, struct tgt_cmnd *cmnd)
{
	struct tgt_vdev *vdev = device->dt_data;
	ssize_t size;
	struct iovec *iov;
	loff_t pos = cmnd->offset;
	int err = 0;

	if (cmnd->bufflen + pos > device->size)
		return -EOVERFLOW;

	iov = sg_to_iovec(cmnd->sg, cmnd->sg_count);
	if (!iov)
		return -ENOMEM;

	if (cmnd->rw == READ)
		size = generic_file_readv(vdev->filp, iov, cmnd->sg_count, &pos);
	else
		size = generic_file_writev(vdev->filp, iov, cmnd->sg_count, &pos);

	kfree(iov);

/* not yet used
	if (sync)
		err = sync_page_range(inode, inode->i_mapping, pos,
				      (size_t) cmnd->bufflen);
*/
	if ((size != cmnd->bufflen) || err)
		return -EIO;
	else
		return 0;
}

static struct tgt_device_template tgt_vdev = {
	.name = "tgt_vdev",
	.module = THIS_MODULE,
	.create = tgt_vdev_create,
	.destroy = tgt_vdev_destroy,
	.queue_cmnd = tgt_vdev_queue,
	.priv_data_size = sizeof(struct tgt_vdev),
};

static int __init tgt_vdev_init(void)
{
	return tgt_device_template_register(&tgt_vdev);
}

static void __exit tgt_vdev_exit(void)
{
	tgt_device_template_unregister(&tgt_vdev);
}

module_init(tgt_vdev_init);
module_exit(tgt_vdev_exit);
MODULE_LICENSE("GPL");
