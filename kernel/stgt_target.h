/*
 * STGT target definitions
 *
 * (C) 2005 FUJITA Tomonori <tomof@acm.org>
 * (C) 2005 Mike Christie <michaelc@cs.wisc.edu>
 * This code is licenced under the GPL.
 */
#ifndef __SCSI_STGT_TARGET_H
#define __SCSI_STGT_TARGET_H

#include <linux/device.h>
#include <linux/list.h>

struct stgt_target_template {
	const char *name;

	int queued_cmnds;
	/*
	 * Pointer to the sysfs class properties for this host, NULL terminated.
	 */
	struct class_device_attribute **target_attrs;
};

struct stgt_target {
	struct stgt_target_template *stt;
	struct class_device cdev;

	int queued_cmnds;

	/* Protects session_list, work_list, device_list */
	spinlock_t lock;

	struct list_head tlist;

	struct list_head device_list;
	struct list_head session_list;

	struct work_struct work;
	struct list_head work_list;
};

#define cdev_to_stgt_target(cdev) \
	container_of(cdev, struct stgt_target, cdev)

extern struct stgt_target *stgt_target_create(struct stgt_target_template *stt);
extern int stgt_target_destroy(struct stgt_target *target);
extern int stgt_sysfs_register_target(struct stgt_target *target);
extern void stgt_sysfs_unregister_target(struct stgt_target *target);

#endif
