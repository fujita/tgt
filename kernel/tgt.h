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

struct tgt_session {
	struct tgt_target *target;
	struct list_head slist;

	mempool_t *cmnd_pool;
};

struct tgt_cmnd {
	struct tgt_session *session;

	uint32_t state;
	uint64_t dev_id;
	uint64_t cid;

	int rw;

	struct work_struct work;
	void (*done) (struct tgt_cmnd *);

	struct list_head clist;
	struct list_head hash_list;

	int sg_count;
	struct scatterlist *sg;
	uint32_t bufflen;
	uint64_t offset;
	int result;

	/* TODO: there should be a better way. */
	uint8_t *error_buff;
	int error_buff_len;

	/*
	 * target driver private
	 */
	void *private;

	void *tgt_protocol_private;
};

extern struct tgt_session *
tgt_session_create(struct tgt_target *target,
		   int max_cmnds,
		   void (*done)(void *, struct tgt_session *), void *arg);
extern int tgt_session_destroy(struct tgt_session *session);

extern int tgt_msg_send(struct tgt_target *target, void *data, int data_len,
			unsigned int gfp_flags);
extern struct tgt_cmnd *tgt_cmnd_create(struct tgt_session *session,
					uint8_t *proto_data,
					uint8_t *id_buff, int buff_size);
extern void tgt_cmnd_destroy(struct tgt_cmnd *cmnd);
extern void tgt_cmnd_alloc_buffer(struct tgt_cmnd *cmnd,
				  void (*done)(struct tgt_cmnd *));
extern int tgt_cmnd_queue(struct tgt_cmnd *cmnd,
			  void (*done)(struct tgt_cmnd *));
extern int tgt_sysfs_init(void);
extern void tgt_sysfs_exit(void);
#endif
