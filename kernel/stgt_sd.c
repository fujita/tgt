/*
 * STGT passthrough device
 *
 * (C) 2005 FUJITA Tomonori <tomof@acm.org>
 * (C) 2005 Mike Christie <michaelc@cs.wisc.edu>
 * This code is licenced under the GPL.
 */
#include <linux/types.h>
#include <linux/blkdev.h>
#include <linux/namei.h>

#include <stgt_device.h>

struct stgt_sd_dev {
	struct block_device *bdev;
};

/*
 * Convert a device path to a dev_t.
 * from dm-table.c
 */
static int lookup_device(const char *path, dev_t *dev)
{
	int r;
	struct nameidata nd;
	struct inode *inode;

	r = path_lookup(path, LOOKUP_FOLLOW, &nd);
	if (r)
		return r;

	inode = nd.dentry->d_inode;
	if (!inode) {
		r = -ENOENT;
		goto out;
	}

	if (!S_ISBLK(inode->i_mode)) {
		r = -ENOTBLK;
		goto out;
	}

	*dev = inode->i_rdev;
out:
	path_release(&nd);
	return r;
}

static int open_dev(struct stgt_sd_dev *sddev, dev_t devt)
{
        struct block_device *bdev;

        bdev = open_by_devnum(devt, FMODE_WRITE | FMODE_READ);
        if (IS_ERR(bdev))
                return PTR_ERR(bdev);
	sddev->bdev = bdev;
        return 0;
}

/*
 * Close a device that we've been using.
 */
static void close_dev(struct stgt_sd_dev *sddev)
{
	blkdev_put(sddev->bdev);
}

static int stgt_sd_create(struct stgt_device *device)
{
	struct stgt_sd_dev *sddev = device->sdt_data;
	dev_t devt;
	int err;

	err = lookup_device(device->path, &devt);
	if (err)
		return err;

	err = open_dev(sddev, devt);
	if (err)
		return err;

	device->size = sddev->bdev->bd_block_size;

	return 0;
}

static void stgt_sd_destroy(struct stgt_device *device)
{
	close_dev(device->sdt_data);
}

static int stgt_sd_queue(struct stgt_device *device, struct stgt_cmnd *cmnd)
{
	/*
	struct stgt_sd_dev *sddev = device->sdt_data;
	struct request_queue *q = bdev_get_queue(sddev->bdev);
	struct request *rq;

	 * format struct request as BLOCK_PC command and do
	 * elv_add_request or if James's no_wait helper is in
	 * then use it
	 *
	 * Will need some stgt wrappers/helpers though
	 */
	return 0;
}

static struct stgt_device_template stgt_sd = {
	.name = "stgt_sd",
	.module = THIS_MODULE,
	.create = stgt_sd_create,
	.destroy = stgt_sd_destroy,
	.queue_cmnd = stgt_sd_queue,
};

static int __init stgt_sd_init(void)
{
	stgt_sd.priv_data_size = sizeof(struct stgt_sd_dev);
	return stgt_device_template_register(&stgt_sd);
}

static void __exit stgt_sd_exit(void)
{
	stgt_device_template_unregister(&stgt_sd);
}

module_init(stgt_sd_init);
module_exit(stgt_sd_exit);
MODULE_LICENSE("GPL");
