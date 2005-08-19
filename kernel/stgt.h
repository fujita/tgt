/*
 * (C) 2005 FUJITA Tomonori <tomof@acm.org>
 * This code is licenced under the GPL.
 */

#ifndef __SCSI_TARGET_H
#define __SCSI_TARGET_H

#include <scsi/scsi_cmnd.h>

struct stgt_target {
	/* Protects session_list, work_list, device_list */
	spinlock_t lock;

	struct list_head tlist;

	struct list_head device_list;
	struct list_head session_list;

	struct work_struct work;
	struct list_head work_list;
};

struct stgt_session {
	struct stgt_target *target;
	struct list_head slist;

	mempool_t *cmnd_pool;
	mempool_t *work_pool;
};

struct stgt_cmnd {
	struct stgt_session *session;

	uint32_t state;
	uint32_t lun;
	uint64_t cid;

	uint8_t scb[MAX_COMMAND_SIZE];

	void (*done) (struct stgt_cmnd *);

	struct list_head clist;
	struct list_head hash_list;

	int sg_count;
	struct scatterlist *sg;
	uint32_t bufflen;

	uint8_t sense_buffer[SCSI_SENSE_BUFFERSIZE];

	void *private;
};

struct stgt_device {
	char *path;
	uint32_t lun;
	uint32_t blk_shift;
	uint64_t blk_count;

	struct stgt_target *target;
	struct list_head dlist;
};

extern struct stgt_target *stgt_target_create(void);
extern int stgt_target_destroy(struct stgt_target *target);

extern struct stgt_session *
stgt_session_create(struct stgt_target *target,
		    int max_cmnds,
		    void (*done)(void *, struct stgt_session *), void *arg);
extern int stgt_session_destroy(struct stgt_session *session);

extern struct stgt_cmnd *stgt_cmnd_create(struct stgt_session *session);
extern void stgt_cmnd_destroy(struct stgt_cmnd *cmnd);
extern void stgt_cmnd_alloc_buffer(struct stgt_cmnd *cmnd,
				  void (*done)(struct stgt_cmnd *));
extern int stgt_cmnd_queue(struct stgt_cmnd *cmnd,
			   void (*done)(struct stgt_cmnd *));

extern struct stgt_device*
stgt_device_create(struct stgt_target *target, char *path, uint32_t lun,
		   unsigned long dflags);
extern int stgt_device_destroy(struct stgt_device *device);

#endif
