/*
 * Copyright (C) 2002-2003 Ardis Technolgies <roman@ardistech.com>
 *
 * Released under the terms of the GNU GPL v2.0.
 */

#ifndef __ISCSI_H__
#define __ISCSI_H__

#include <linux/pagemap.h>
#include <linux/mm.h>
#include <linux/crypto.h>
#include <net/sock.h>
#include <asm/scatterlist.h>

#include "iscsi_proto.h"
#include "iet_u.h"

struct iscsi_sess_param {
	int initial_r2t;
	int immediate_data;
	int max_connections;
	int max_recv_data_length;
	int max_xmit_data_length;
	int max_burst_length;
	int first_burst_length;
	int default_wait_time;
	int default_retain_time;
	int max_outstanding_r2t;
	int data_pdu_inorder;
	int data_sequence_inorder;
	int error_recovery_level;
	int header_digest;
	int data_digest;
	int ofmarker;
	int ifmarker;
	int ofmarkint;
	int ifmarkint;
};

struct iscsi_trgt_param {
	int target_type;
	int queued_cmnds;
};

struct network_thread_info {
	struct task_struct *task;
	unsigned long flags;
	struct list_head active_conns;

	spinlock_t nthread_lock;

	void (*old_state_change)(struct sock *);
	void (*old_data_ready)(struct sock *, int);
};

struct iscsi_cmnd;

enum iscsi_device_state {
	IDEV_RUNNING,
	IDEV_DEL,
};

struct iscsi_target {
	int tid;

	struct iscsi_sess_param sess_param;
	struct iscsi_trgt_param trgt_param;

	struct list_head session_list;
	struct network_thread_info nthread_info;
	struct semaphore target_sem;

	struct tgt_target *tt;
};

#define IET_HASH_ORDER		8
#define	cmnd_hashfn(itt)	hash_long((itt), IET_HASH_ORDER)

struct iscsi_session {
	struct list_head list;
	struct iscsi_target *target;

	u64 sid;

	u32 exp_cmd_sn;
	u32 max_cmd_sn;

	struct iscsi_sess_param param;
	u32 max_queued_cmnds;

	struct list_head conn_list;
	struct list_head pending_list;

	spinlock_t cmnd_hash_lock;
	struct list_head cmnd_hash[1 << IET_HASH_ORDER];

	u32 next_ttt;

	struct tgt_session *ts;
};

enum connection_state_bit {
	CONN_ACTIVE,
	CONN_CLOSING,
};

#define ISCSI_CONN_IOV_MAX	(((256 << 10) >> PAGE_SHIFT) + 1)

struct iscsi_conn {
	struct list_head list;			/* list entry in session list */
	struct iscsi_session *session;		/* owning session */

	u16 cid;
	unsigned long state;

	u32 stat_sn;
	u32 exp_stat_sn;

	int hdigest_type;
	int ddigest_type;

	struct list_head poll_list;

	struct file *file;
	struct socket *sock;
	spinlock_t list_lock;
	atomic_t nr_cmnds;
	atomic_t nr_busy_cmnds;
	struct list_head pdu_list;		/* in/outcoming pdus */
	struct list_head write_list;		/* list of data pdus to be sent */

	struct iscsi_cmnd *read_cmnd;
	struct msghdr read_msg;
	struct iovec read_iov[ISCSI_CONN_IOV_MAX];
	u32 read_size;
	u32 read_overflow;
	int read_state;

	struct iscsi_cmnd *write_cmnd;
	struct iovec write_iov[ISCSI_CONN_IOV_MAX];
	struct iovec *write_iop;

	struct scatterlist *write_tcmnd;

	u32 write_size;
	u32 write_offset;
	int write_state;

	struct crypto_tfm *rx_digest_tfm;
	struct crypto_tfm *tx_digest_tfm;
};

struct iscsi_pdu {
	struct iscsi_hdr bhs;
	void *ahs;
	unsigned int ahssize;
	unsigned int datasize;
};

struct iscsi_cmnd {
	struct list_head list;
	struct list_head conn_list;
	unsigned long state;
	unsigned long flags;
	struct iscsi_conn *conn;

	struct iscsi_pdu pdu;
	struct list_head pdu_list;

	struct list_head hash_list;

	struct scatterlist *sg, sense_sg;

	u32 r2t_sn;
	u32 r2t_length;
	u32 is_unsolicited_data;
	u32 target_task_tag;
	u32 outstanding_r2t;

	u32 hdigest;
	u32 ddigest;

	struct iscsi_cmnd *req;
	struct tgt_cmd *tc;
};

#define ISCSI_OP_SCSI_REJECT	ISCSI_OP_VENDOR1_CMD
#define ISCSI_OP_PDU_REJECT	ISCSI_OP_VENDOR2_CMD
#define ISCSI_OP_DATA_REJECT	ISCSI_OP_VENDOR3_CMD
#define ISCSI_OP_SCSI_ABORT	ISCSI_OP_VENDOR4_CMD

/* iscsi.c */
extern struct iscsi_cmnd *cmnd_alloc(struct iscsi_conn *, int);
extern void cmnd_rx_start(struct iscsi_cmnd *);
extern void cmnd_rx_end(struct iscsi_cmnd *);
extern void cmnd_tx_start(struct iscsi_cmnd *);
extern void cmnd_tx_end(struct iscsi_cmnd *);
extern void cmnd_release(struct iscsi_cmnd *, int);
extern void send_scsi_rsp(struct iscsi_cmnd *);

/* conn.c */
extern struct iscsi_conn *conn_lookup(struct iscsi_session *, u16);
extern int conn_add(struct iscsi_session *, struct conn_info *);
extern int conn_del(struct iscsi_session *, struct conn_info *);
extern int conn_free(struct iscsi_conn *);
extern void conn_close(struct iscsi_conn *);

/* nthread.c */
extern int nthread_init(struct iscsi_target *);
extern int nthread_start(struct iscsi_target *);
extern int nthread_stop(struct iscsi_target *);
extern void nthread_wakeup(struct iscsi_target *);

/* target.c */
extern int target_lock(struct iscsi_target *, int);
extern void target_unlock(struct iscsi_target *);
extern int target_add(struct tgt_target *);
extern void target_del(struct tgt_target *);

/* config.c */
extern int iet_msg_recv(struct tgt_target *, uint32_t, void *);
extern int event_send(struct tgt_target *tgt, u32 tid, u64 sid, u32 cid, u32 state);

/* session.c */
extern struct iscsi_session *session_lookup(struct iscsi_target *, u64);
extern int session_add(struct iscsi_target *, struct session_info *);
extern int session_del(struct iscsi_target *, u64);

/* params.c */
extern int iscsi_param_set(struct iscsi_target *, struct iscsi_param_info *, int);

#define get_pgcnt(size, offset)	((((size) + ((offset) & ~PAGE_CACHE_MASK)) + PAGE_CACHE_SIZE - 1) >> PAGE_CACHE_SHIFT)

static inline void iscsi_cmnd_get_length(struct iscsi_pdu *pdu)
{
	pdu->ahssize = pdu->bhs.hlength * 4;
	pdu->datasize = ntoh24(pdu->bhs.dlength);
}

static inline void iscsi_cmnd_set_length(struct iscsi_pdu *pdu)
{
	pdu->bhs.hlength = pdu->ahssize / 4;
	hton24(pdu->bhs.dlength, pdu->datasize);
}

#define cmnd_hdr(cmnd) ((struct iscsi_cmd *) (&((cmnd)->pdu.bhs)))
#define cmnd_ttt(cmnd) cpu_to_be32((cmnd)->pdu.bhs.ttt)
#define cmnd_itt(cmnd) cpu_to_be32((cmnd)->pdu.bhs.itt)
#define cmnd_opcode(cmnd) ((cmnd)->pdu.bhs.opcode & ISCSI_OPCODE_MASK)
#define cmnd_scsicode(cmnd) cmnd_hdr(cmnd)->cdb[0]

#define	SECTOR_SIZE_BITS	9

enum cmnd_flags {
	CMND_hashed,
	CMND_queued,
	CMND_final,
	CMND_waitio,
	CMND_close,
	CMND_lunit,
	CMND_pending,
};

#define set_cmnd_hashed(cmnd)	set_bit(CMND_hashed, &(cmnd)->flags)
#define cmnd_hashed(cmnd)	test_bit(CMND_hashed, &(cmnd)->flags)

#define set_cmnd_queued(cmnd)	set_bit(CMND_queued, &(cmnd)->flags)
#define cmnd_queued(cmnd)	test_bit(CMND_queued, &(cmnd)->flags)

#define set_cmnd_final(cmnd)	set_bit(CMND_final, &(cmnd)->flags)
#define cmnd_final(cmnd)	test_bit(CMND_final, &(cmnd)->flags)

#define set_cmnd_waitio(cmnd)	set_bit(CMND_waitio, &(cmnd)->flags)
#define cmnd_waitio(cmnd)	test_bit(CMND_waitio, &(cmnd)->flags)

#define set_cmnd_close(cmnd)	set_bit(CMND_close, &(cmnd)->flags)
#define cmnd_close(cmnd)	test_bit(CMND_close, &(cmnd)->flags)

#define set_cmnd_pending(cmnd)	set_bit(CMND_pending, &(cmnd)->flags)
#define clear_cmnd_pending(cmnd)	clear_bit(CMND_pending, &(cmnd)->flags)
#define cmnd_pending(cmnd)	test_bit(CMND_pending, &(cmnd)->flags)

/* We still use 'IET' id. Maybe someday, we get own id. */

#define VENDOR_ID	"IET"
#define PRODUCT_ID	"VIRTUAL-DISK"
#define PRODUCT_REV	"0"

#endif	/* __ISCSI_H__ */
