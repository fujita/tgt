/*
 * Target Framework Device definitions
 *
 * (C) 2005 FUJITA Tomonori <tomof@acm.org>
 * (C) 2005 Mike Christie <michaelc@cs.wisc.edu>
 * This code is licenced under the GPL.
 */
#ifndef __TGT_DEVICE_H
#define __TGT_DEVICE_H

#include <linux/blkdev.h>
#include <linux/device-mapper.h>
#include <linux/device.h>
#include <linux/list.h>

struct tgt_device;
struct tgt_cmd;

enum {
	TGT_CMD_COMPLETED,
	TGT_CMD_FAILED,
	/*
	 * if the device has queued the command it is responsible for
	 * for completing it
	 */
	TGT_CMD_USPACE_QUEUED,
	TGT_CMD_KERN_QUEUED,
	TGT_DEV_DEL = 0,
};

/*
 * TODO: we could do a queue per target instead of per device and kill
 * all the tgt_device code
 */
struct tgt_device {
	struct class_device cdev;

	int fd;
	struct file *file;
	uint64_t dev_id;
	uint32_t blk_shift;
	uint64_t size;

	unsigned long state;

	struct tgt_target *target;
	struct list_head dlist;
};

#define cdev_to_tgt_device(cdev) \
        container_of(cdev, struct tgt_device, cdev)

extern void tgt_device_free(struct tgt_device *device);
extern struct tgt_device *tgt_device_get(struct tgt_target *target,
					 uint64_t dev_id);
extern void tgt_device_put(struct tgt_device *device);


extern int tgt_sysfs_register_device(struct tgt_device *device);
extern void tgt_sysfs_unregister_device(struct tgt_device *device);

#endif
