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

enum {
	TGT_CMND_COMPLETED,
	TGT_CMND_FAILED,
	/*
	 * if the device has queued the command it is responsible for
	 * for completing it
	 */
	TGT_CMND_USPACE_QUEUED,
	TGT_CMND_KERN_QUEUED
};

struct tgt_device_template {
	const char *name;
	struct module *module;
	unsigned priv_data_size;

	/*
	 * setup and destroy private structures
	 */
	int (* create)(struct tgt_device *);
	void (* destroy)(struct tgt_device *);
	/*
	 * queue or execute command. Return TGT_CMND*.
	 * If returning TGT_CMND_COMPLETED or TGT_CMND_FAILED the result
	 * field must be set.
	 */
	int (* queue_cmnd)(struct tgt_cmnd *cmnd);
	/*
	 * complete a userspace command
	 */
	void ( *complete_uspace_cmnd)(struct tgt_cmnd *cmnd);
	/*
	 * complete a kernel command if your queue_command was async
	 * and the device used one of the tgt threads to process the
	 * command
	 */
	void (*complete_kern_cmnd)(struct tgt_cmnd *cmnd);
	/*
	 * setup buffer or device fields if needed
	 */
	void (* prep_cmnd)(struct tgt_cmnd *cmnd);

	/*
	 * Pointer to the sysfs class properties for this host, NULL terminated.
	 */
	struct class_device_attribute **device_attrs;
};

struct tgt_device {
	struct tgt_device_template *dt;
	void *dt_data;

	struct class_device cdev;

	int fd;
	struct file *file;
	uint64_t dev_id;
	uint32_t blk_shift;
	uint64_t size;

	struct tgt_target *target;
	struct list_head dlist;
};

#define cdev_to_tgt_device(cdev) \
        container_of(cdev, struct tgt_device, cdev)

extern struct tgt_device *tgt_device_find(struct tgt_target *target,
					  uint64_t dev_id);
extern int tgt_sysfs_register_device(struct tgt_device *device);
extern void tgt_sysfs_unregister_device(struct tgt_device *device);
extern int tgt_device_template_register(struct tgt_device_template *dt);
extern void tgt_device_template_unregister(struct tgt_device_template *dt);

#endif
