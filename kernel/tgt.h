/*
 * Core Target Framework definitions
 *
 * (C) 2005 FUJITA Tomonori <tomof@acm.org>
 * (C) 2005 Mike Christie <michaelc@cs.wisc.edu>
 * This code is licenced under the GPL.
 */

#ifndef __TGT_H
#define __TGT_H

#include <linux/mempool.h>
#include <linux/dma-mapping.h>

struct tgt_device;
struct tgt_protocol;

struct tgt_session {
	struct tgt_target *target;
	struct list_head slist;

	mempool_t *cmnd_pool;
};

struct tgt_cmnd {
	struct tgt_session *session;
	struct tgt_device *device;
	struct tgt_protocol *proto;

	uint32_t state;
	uint64_t dev_id;
	uint64_t cid;

	struct work_struct work;
	void (*done) (struct tgt_cmnd *);

	struct list_head clist;
	struct list_head hash_list;

	enum dma_data_direction data_dir;
	int sg_count;
	struct scatterlist *sg;
	uint32_t bufflen;
	uint64_t offset;
	int result;

	/*
	 * target driver private
	 */
	void *private;

	/*
	 * is the alignment still needed?  See scsi_host.h
	 */
	unsigned long proto_priv[0] __attribute__ ((aligned (sizeof(unsigned long))));
};

extern struct tgt_session *
tgt_session_create(struct tgt_target *target,
		   int max_cmnds,
		   void (*done)(void *, struct tgt_session *), void *arg);
extern int tgt_session_destroy(struct tgt_session *session);

extern int tgt_msg_send(struct tgt_target *target, void *data, int data_len,
			unsigned int gfp_flags);
extern int tgt_uspace_cmnd_send(struct tgt_cmnd *cmnd);
extern struct tgt_cmnd *tgt_cmnd_create(struct tgt_session *session);
extern void tgt_cmnd_destroy(struct tgt_cmnd *cmnd);
extern void tgt_cmnd_alloc_buffer(struct tgt_cmnd *cmnd,
				  void (*done)(struct tgt_cmnd *));
extern int tgt_cmnd_queue(struct tgt_cmnd *cmnd,
			  void (*done)(struct tgt_cmnd *));
extern int tgt_sysfs_init(void);
extern void tgt_sysfs_exit(void);
#endif
