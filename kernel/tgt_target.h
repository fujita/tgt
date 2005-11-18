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
struct tgt_cmd;

struct target_type_internal {
	int typeid;
	struct list_head list;
	struct tgt_target_template *tt;
	struct tgt_protocol *proto;
	struct class_device cdev;
};

enum {
	TGT_CMD_XMIT_OK,
	TGT_CMD_XMIT_FAILED,
	TGT_CMD_XMIT_REQUEUE,
};

#define TGT_DEFAULT_MAX_SECTORS 1024
#define TGT_MAX_PHYS_SEGMENTS 255
/*
 * this should be a template and device limit probably
 */
#define TGT_QUEUE_DEPTH 64

struct tgt_target_template {
	const char *name;
	struct module *module;
	unsigned priv_data_size;

	unsigned short max_hw_segments;
	unsigned int max_segment_size;
	unsigned long seg_boundary_mask;
	unsigned short max_sectors;
	unsigned use_clustering;

	/*
	 * Target creation/destroy callbacks useful when userspace
	 * initiates these operations
	 */
	int (* target_create) (struct tgt_target *);
	void (* target_destroy) (struct tgt_target *);
	/*
	 * Called when userspace sends the target a driver specific
	 * message. To send a response the target driver should call
	 * tgt_msg_send.
	 */
	int (* msg_recv) (struct tgt_target *, uint32_t, void *);
	/*
	 * Transfer command response and/or data. If the target driver
	 * cannot queue the request and would like it requeued then it
	 * should return an appropriate TGT_CMD_XMIT_*. When the
	 * the transfer is complete and the target driver is finished with
	 * the command the cmd->done() callback must be called. After the
	 * the cmd->done callback has been called tgt_core owns the cmd and
	 * may free it.
	 *
	 * TODO rename this
	 */
	int (* transfer_response) (struct tgt_cmd *);
	/*
	 * Transfer write data to the sg buffer.
	 *
	 * TODO rename
	 */
	int (* transfer_write_data) (struct tgt_cmd *);

	/*
	 * name of protocol to use
	 */
	const char *protocol;

	/*
	 * name of sub-protocol to use
	 */
	const char *subprotocol;

	/*
	 * Pointer to the sysfs class properties for this host, NULL terminated.
	 */
	struct class_device_attribute **target_attrs;
};

struct tgt_target {
	int typeid;
	int tid;
	struct tgt_target_template *tt;
	void *tt_data;
	struct tgt_protocol *proto;

	struct class_device cdev;

	struct request_queue *q;
	int queued_cmds;

	/* Protects session_list and device_list */
	spinlock_t lock;

	struct list_head tlist;

	struct list_head device_list;
	struct list_head session_list;

	struct workqueue_struct *twq;
};

#define cdev_to_tgt_target(cdev) \
	container_of(cdev, struct tgt_target, cdev)

extern struct tgt_target *tgt_target_create(char *target_type, int nr_cmds);
extern int tgt_target_destroy(struct tgt_target *target);
extern int tgt_sysfs_register_target(struct tgt_target *target);
extern void tgt_sysfs_unregister_target(struct tgt_target *target);

extern int tgt_target_template_register(struct tgt_target_template *tt);
extern void tgt_target_template_unregister(struct tgt_target_template *tt);
extern int tgt_sysfs_register_type(struct target_type_internal *ti);
extern void tgt_sysfs_unregister_type(struct target_type_internal *ti);

#endif
