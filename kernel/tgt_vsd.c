/*
 * Target virtual device functions
 *
 * (C) 2005 FUJITA Tomonori <tomof@acm.org>
 * (C) 2005 Mike Christie <michaelc@cs.wisc.edu>
 * This code is licenced under the GPL.
 */

#include <linux/types.h>
#include <linux/blkdev.h>
#include <linux/namei.h>
#include <linux/uio.h>
#include <linux/fs.h>
#include <linux/writeback.h>

#include <tgt.h>
#include <tgt_device.h>

struct tgt_vsd_dev {
	struct file *filp;
};

static void tgt_vsd_destroy(struct tgt_device *device)
{
	struct tgt_vsd_dev *vsddev = device->dt_data;
	filp_close(vsddev->filp, NULL);
}

static int open_file(struct tgt_vsd_dev *vsddev, const char *path)
{
	struct file *filp;
	mm_segment_t oldfs;
	int err = 0;

	oldfs = get_fs();
	set_fs(get_ds());
	filp = filp_open(path, O_RDWR|O_LARGEFILE, 0);
	set_fs(oldfs);

	if (IS_ERR(filp)) {
		err = PTR_ERR(filp);
		printk("Can't open %s %d\n", path, err);
	} else
		vsddev->filp = filp;

	return err;
}

static int tgt_vsd_create(struct tgt_device *device)
{
	struct tgt_vsd_dev *vsddev = device->dt_data;
	struct inode *inode;
	int err = 0;

	err = open_file(vsddev, device->path);
	if (err)
		return err;

	inode = vsddev->filp->f_dentry->d_inode;
	if (S_ISREG(inode->i_mode))
		;
	else if (S_ISBLK(inode->i_mode))
		inode = inode->i_bdev->bd_inode;
	else {
		err = -EINVAL;
		goto out;
	}

	device->size = inode->i_size;
	printk("%s %llu\n", device->path, inode->i_size >> 9);

	return 0;
out:
	filp_close(vsddev->filp, NULL);
	return err;
}

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

static int tgt_vsd_queue(struct tgt_device *device, struct tgt_cmnd *cmnd)
{
	struct tgt_vsd_dev *vsddev = device->dt_data;
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
		size = generic_file_readv(vsddev->filp, iov, cmnd->sg_count, &pos);
	else
		size = generic_file_writev(vsddev->filp, iov, cmnd->sg_count, &pos);

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

static struct tgt_device_template tgt_vsd = {
	.name = "tgt_vsd",
	.module = THIS_MODULE,
	.create = tgt_vsd_create,
	.destroy = tgt_vsd_destroy,
	.queue_cmnd = tgt_vsd_queue,
	.priv_data_size = sizeof(struct tgt_vsd_dev),
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
