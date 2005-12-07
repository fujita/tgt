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
#include <linux/bio.h>
#include <linux/dma-mapping.h>

#include <tgt_types.h>

struct request;
struct tgt_device;
struct tgt_protocol;
struct tgt_session;

/*
 * this should be in a tgt_target_template
 */
#define	TGT_MAX_CMD	64

typedef void (tgt_session_done_t) (void *, struct tgt_session *);

struct tgt_session {
	struct tgt_target *target;
	struct list_head slist;

	mempool_t *cmd_pool;

	struct work_struct work;
	tgt_session_done_t *done;
	void *arg;
};

enum {
	TGT_CMD_CREATED,
	TGT_CMD_BUF_ALLOCATED,
	TGT_CMD_STARTED,
	TGT_CMD_READY,
	TGT_CMD_RECV,
	TGT_CMD_XMIT,
	TGT_CMD_DONE,
};

struct tgt_cmd {
	struct tgt_session *session;
	struct tgt_device *device;
	struct tgt_protocol *proto;

	atomic_t state;
	uint64_t dev_id;

	struct work_struct work;
	void (*done) (struct tgt_cmd *);

	enum dma_data_direction data_dir;
	int sg_count;
	struct scatterlist *sg;
	uint32_t bufflen;
	uint64_t offset;
	int result;

	struct request *rq;
	/*
	 * target driver private
	 */
	void *private;

	/*
	 * is the alignment still needed?  See scsi_host.h
	 */
	unsigned long proto_priv[0] __attribute__ ((aligned (sizeof(unsigned long))));
};

extern int tgt_session_create(struct tgt_target *target,
			      tgt_session_done_t *done, void *arg);
extern int tgt_session_destroy(struct tgt_session *session,
			       tgt_session_done_t *done, void *arg);
extern int tgt_msg_send(struct tgt_target *target, void *data, int dlen,
			gfp_t flags);
extern int tgt_uspace_cmd_send(struct tgt_cmd *cmd, gfp_t gfp_mask);
extern struct tgt_cmd *
tgt_cmd_create(struct tgt_session *session, void *tgt_priv, uint8_t *cb,
	       uint32_t data_len, enum dma_data_direction data_dir,
	       uint8_t *dev_buf, int dev_buf_size, int flags);
extern int tgt_cmd_start(struct tgt_cmd *cmd);
extern void tgt_transfer_response(void *cmd);

#define DEBUG_TGT

#define eprintk(fmt, args...)					\
do {								\
	printk("%s(%d) " fmt, __FUNCTION__, __LINE__, ##args);	\
} while (0)

#ifdef DEBUG_TGT
#define dprintk eprintk
#else
#define dprintk(fmt, args...)
#endif

#endif
