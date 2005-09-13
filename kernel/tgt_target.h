/*
 * Target Framework Target definitions
 *
 * (C) 2005 FUJITA Tomonori <tomof@acm.org>
 * (C) 2005 Mike Christie <michaelc@cs.wisc.edu>
 * This code is licenced under the GPL.
 */
#ifndef __TGT_TARGET_H
#define __TGT_TARGET_H

#include <linux/device.h>
#include <linux/list.h>

struct tgt_protocol;
struct tgt_target;

struct tgt_target_template {
	const char *name;
	struct module *module;
	unsigned priv_data_size;

	int (* target_create) (struct tgt_target *);
	void (* target_destroy) (struct tgt_target *);

	/*
	 * name of protocol to use
	 */
	const char *protocol;

	/*
	 * Pointer to the sysfs class properties for this host, NULL terminated.
	 */
	struct class_device_attribute **target_attrs;
};

struct tgt_target {
	int tid;
	struct tgt_target_template *tt;
	void *tt_data;
	struct tgt_protocol *proto;

	struct class_device cdev;

	int queued_cmnds;

	/* Protects session_list, work_list, device_list */
	spinlock_t lock;

	struct list_head tlist;

	struct list_head device_list;
	struct list_head session_list;

	struct list_head work_list;
	struct workqueue_struct *twq;
};

#define cdev_to_tgt_target(cdev) \
	container_of(cdev, struct tgt_target, cdev)

extern struct tgt_target *tgt_target_create(char *target_type, int nr_cmnds);
extern int tgt_target_destroy(struct tgt_target *target);
extern int tgt_sysfs_register_target(struct tgt_target *target);
extern void tgt_sysfs_unregister_target(struct tgt_target *target);
extern int tgt_target_template_register(struct tgt_target_template *tt);
extern void tgt_target_template_unregister(struct tgt_target_template *tt);

#endif
