/*
 * STGT virtual device
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
#include <scsi/scsi.h>

#include <stgt.h>
#include <stgt_device.h>

struct stgt_vsd_dev {
	struct file *filp;
};

static void stgt_vsd_destroy(struct stgt_device *device)
{
	struct stgt_vsd_dev *vsddev = device->sdt_data;
	filp_close(vsddev->filp, NULL);
}

static int open_file(struct stgt_vsd_dev *vsddev, const char *path)
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

static int stgt_vsd_create(struct stgt_device *device)
{
	struct stgt_vsd_dev *vsddev = device->sdt_data;
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

static loff_t translate_offset(uint8_t *scb)
{
	loff_t off = 0;

	switch (scb[0]) {
	case READ_6:
	case WRITE_6:
		off = ((scb[1] & 0x1f) << 16) + (scb[2] << 8) + scb[3];
		break;
	case READ_10:
	case WRITE_10:
	case WRITE_VERIFY:
		off = be32_to_cpu(*(u32 *)&scb[2]);
		break;
	case READ_16:
	case WRITE_16:
		off = be64_to_cpu(*(u64 *)&scb[2]);
		break;
	default:
		BUG();
	}

	return off << 9;
}

static struct iovec* sg_to_iovec(struct scatterlist *sg, int sg_count)
{
	struct iovec* iov;
	int i;

	iov = kmalloc(sizeof(struct iovec) * sg_count, GFP_KERNEL);
	if (!iov) {
		printk("%s %d ENOMEM %d\n", __FUNCTION__, __LINE__, sg_count);
		return NULL;
	}

	for (i = 0; i < sg_count; i++) {
		iov[i].iov_base = page_address(sg[i].page) + sg[i].offset;
		iov[i].iov_len = sg[i].length;
	}

	return iov;
}

static int stgt_vsd_queue(struct stgt_device *device, struct stgt_cmnd *cmnd)
{
	struct stgt_vsd_dev *vsddev = device->sdt_data;
	loff_t pos = translate_offset(cmnd->scb);
	ssize_t size;
	struct iovec *iov = NULL;
	int err = 0;

	switch (cmnd->scb[0]) {
	case READ_6:
	case READ_10:
	case READ_16:
		iov = sg_to_iovec(cmnd->sg, cmnd->sg_count);
		if (!iov)
			goto out;
		size = generic_file_readv(vsddev->filp, iov, cmnd->sg_count, &pos);
		kfree(iov);
		break;
	case WRITE_6:
	case WRITE_10:
	case WRITE_16:
	case WRITE_VERIFY:
		iov = sg_to_iovec(cmnd->sg, cmnd->sg_count);
		if (!iov)
			goto out;
		err = generic_file_writev(vsddev->filp, iov, cmnd->sg_count, &pos);
		kfree(iov);
		break;
	case RESERVE:
	case RELEASE:
	case RESERVE_10:
	case RELEASE_10:
		break;
	default:
		BUG();
	}

	if (err < 0)
		printk("%s %d: %d %llu\n", __FUNCTION__, __LINE__, err, pos);
out:
	return 0;
}

static int stgt_vsd_prep(struct stgt_device *device, struct stgt_cmnd *cmnd)
{
	enum stgt_cmnd_type type;

	switch (cmnd->scb[0]) {
	case READ_6:
	case READ_10:
	case READ_16:
	case WRITE_6:
	case WRITE_10:
	case WRITE_16:
	case WRITE_VERIFY:
	case RESERVE:
	case RELEASE:
	case RESERVE_10:
	case RELEASE_10:
		type = STGT_CMND_KSPACE;
		break;
	default:
		type = STGT_CMND_USPACE;
	}

	return type;
}

static struct stgt_device_template stgt_vsd = {
	.name = "stgt_vsd",
	.module = THIS_MODULE,
	.create = stgt_vsd_create,
	.destroy = stgt_vsd_destroy,
	.queuecommand = stgt_vsd_queue,
	.prepcommand = stgt_vsd_prep,
};

static int __init stgt_vsd_init(void)
{
	stgt_vsd.priv_data_size = sizeof(struct stgt_vsd_dev);
	return stgt_device_template_register(&stgt_vsd);
}

static void __exit stgt_vsd_exit(void)
{
	stgt_device_template_unregister(&stgt_vsd);
}

module_init(stgt_vsd_init);
module_exit(stgt_vsd_exit);
MODULE_LICENSE("GPL");
