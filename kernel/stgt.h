/*
 * (C) 2005 FUJITA Tomonori <tomof@acm.org>
 * (C) 2005 Mike Christie <michaelc@cs.wisc.edu>
 * This code is licenced under the GPL.
 */

#ifndef __SCSI_TARGET_H
#define __SCSI_TARGET_H

#include <linux/mempool.h>
#include <scsi/scsi_cmnd.h>

struct stgt_session {
	struct stgt_target *target;
	struct list_head slist;

	mempool_t *cmnd_pool;
	mempool_t *work_pool;
};

struct stgt_cmnd {
	struct stgt_session *session;

	uint32_t state;
	uint64_t dev_id;
	uint64_t cid;

	int rw;

	void (*done) (struct stgt_cmnd *);

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

extern struct stgt_session *
stgt_session_create(struct stgt_target *target,
		    int max_cmnds,
		    void (*done)(void *, struct stgt_session *), void *arg);
extern int stgt_session_destroy(struct stgt_session *session);

extern struct stgt_cmnd *stgt_cmnd_create(struct stgt_session *session,
					  uint8_t *proto_data,
					  uint8_t *id_buff, int buff_size);
extern void stgt_cmnd_destroy(struct stgt_cmnd *cmnd);
extern void stgt_cmnd_alloc_buffer(struct stgt_cmnd *cmnd,
				  void (*done)(struct stgt_cmnd *));
extern int stgt_cmnd_queue(struct stgt_cmnd *cmnd,
			   void (*done)(struct stgt_cmnd *));
extern int stgt_sysfs_init(void);
extern void stgt_sysfs_exit(void);
#endif
