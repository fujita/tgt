/*
 * Target Framework Device definitions
 *
 * (C) 2005 FUJITA Tomonori <tomof@acm.org>
 * (C) 2005 Mike Christie <michaelc@cs.wisc.edu>
 * This code is licenced under the GPL.
 */
#ifndef __TGT_DEVICE_H
#define __TGT_DEVICE_H

#include <linux/device.h>
#include <linux/list.h>

struct tgt_device;
struct tgt_cmnd;

struct tgt_device_template {
	const char *name;
	struct module *module;
	unsigned priv_data_size;

	int (* create)(struct tgt_device *);
	void (* destroy)(struct tgt_device *);
	int (* queue_cmnd)(struct tgt_device *device, struct tgt_cmnd *cmnd);

	/*
	 * Pointer to the sysfs class properties for this host, NULL terminated.
	 */
	struct class_device_attribute **device_attrs;
};

struct tgt_device {
	struct tgt_device_template *dt;
	void *dt_data;

	struct class_device cdev;

	char *path;
	uint64_t dev_id;
	uint32_t blk_shift;
	uint64_t size;

	struct tgt_target *target;
	struct list_head dlist;
};

#define cdev_to_tgt_device(cdev) \
        container_of(cdev, struct tgt_device, cdev)

extern int tgt_sysfs_register_device(struct tgt_device *device);
extern void tgt_sysfs_unregister_device(struct tgt_device *device);
extern int tgt_device_template_register(struct tgt_device_template *dt);
extern void tgt_device_template_unregister(struct tgt_device_template *dt);

#endif
