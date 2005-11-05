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

#include <iscsi_proto.h>
#include <istgt_u.h>

#include <tgt.h>
#include <tgt_target.h>
#include <tgt_scsi.h>
#include <tgt_protocol.h>

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

struct istgt_cmd;

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

	uint64_t sid;

	uint32_t exp_cmd_sn;
	uint32_t max_cmd_sn;

	struct iscsi_sess_param param;
	uint32_t max_queued_cmnds;

	struct list_head conn_list;
	struct list_head pending_list;

	spinlock_t cmnd_hash_lock;
	struct list_head cmnd_hash[1 << IET_HASH_ORDER];

	uint32_t next_ttt;

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

	uint16_t cid;
	unsigned long state;

	uint32_t stat_sn;
	uint32_t exp_stat_sn;

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

	struct istgt_cmd *read_cmnd;
	struct msghdr read_msg;
	struct iovec read_iov[ISCSI_CONN_IOV_MAX];
	uint32_t read_size;
	uint32_t read_overflow;
	int read_state;

	struct istgt_cmd *write_cmnd;
	struct iovec write_iov[ISCSI_CONN_IOV_MAX];
	struct iovec *write_iop;

	struct scatterlist *write_tcmnd;

	uint32_t write_size;
	uint32_t write_offset;
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

struct istgt_cmd {
	struct list_head list;
	struct list_head conn_list;
	unsigned long state;
	unsigned long flags;
	struct iscsi_conn *conn;

	struct iscsi_pdu pdu;
	struct list_head pdu_list;

	struct list_head hash_list;

	struct scatterlist *sg, sense_sg;

	uint32_t r2t_sn;
	uint32_t r2t_length;
	uint32_t is_unsolicited_data;
	uint32_t target_task_tag;
	uint32_t outstanding_r2t;

	uint32_t hdigest;
	uint32_t ddigest;

	struct work_struct work;
	struct completion event;

	struct istgt_cmd *req;
	struct tgt_cmd *tc;
};

#define ISCSI_OP_SCSI_REJECT	ISCSI_OP_VENDOR1_CMD
#define ISCSI_OP_PDU_REJECT	ISCSI_OP_VENDOR2_CMD
#define ISCSI_OP_DATA_REJECT	ISCSI_OP_VENDOR3_CMD
#define ISCSI_OP_SCSI_ABORT	ISCSI_OP_VENDOR4_CMD

/* iscsi.c */
extern struct istgt_cmd *cmnd_alloc(struct iscsi_conn *, int);
extern void cmnd_rx_start(struct istgt_cmd *);
extern void cmnd_rx_end(struct istgt_cmd *);
extern void cmnd_tx_start(struct istgt_cmd *);
extern void cmnd_tx_end(struct istgt_cmd *);
extern void cmnd_release(struct istgt_cmd *, int);
extern void send_scsi_rsp(struct istgt_cmd *);

/* conn.c */
extern int conn_add(struct iscsi_session *, struct conn_info *);
extern int conn_del(struct iscsi_session *, struct conn_info *);
extern int conn_free(struct iscsi_conn *);
extern void conn_close(struct iscsi_conn *);

/* nthread.c */
extern int nthread_init(struct iscsi_target *);
extern int nthread_start(struct iscsi_target *);
extern int nthread_stop(struct iscsi_target *);
extern void nthread_wakeup(struct iscsi_target *);

/* config.c */
extern int iet_msg_recv(struct tgt_target *, uint32_t, void *);
extern int event_send(struct tgt_target *tgt, int tid, uint64_t sid,
		      uint32_t cid, uint32_t state);

/* session.c */
extern struct iscsi_session *session_lookup(struct iscsi_target *, uint64_t);
extern int session_add(struct iscsi_target *, struct session_info *);
extern int session_del(struct iscsi_target *, uint64_t);

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

#define cmd_hdr(cmd) ((struct iscsi_cmd *) (&((cmd)->pdu.bhs)))
#define cmd_ttt(cmd) cpu_to_be32((cmd)->pdu.bhs.ttt)
#define cmd_itt(cmd) cpu_to_be32((cmd)->pdu.bhs.itt)
#define cmd_opcode(cmd) ((cmd)->pdu.bhs.opcode & ISCSI_OPCODE_MASK)
#define cmd_scsicode(cmd) cmd_hdr(cmd)->cdb[0]

#define	SECTOR_SIZE_BITS	9

enum istgt_cmd_flags {
	CMD_hashed,
	CMD_final,
	CMD_waitio,
	CMD_close,
	CMD_lunit,
	CMD_pending,
};

#define set_cmd_hashed(cmd)	set_bit(CMD_hashed, &(cmd)->flags)
#define cmd_hashed(cmd)	test_bit(CMD_hashed, &(cmd)->flags)

#define set_cmd_final(cmd)	set_bit(CMD_final, &(cmd)->flags)
#define cmd_final(cmd)	test_bit(CMD_final, &(cmd)->flags)

#define set_cmd_waitio(cmd)	set_bit(CMD_waitio, &(cmd)->flags)
#define cmd_waitio(cmd)	test_bit(CMD_waitio, &(cmd)->flags)

#define set_cmd_close(cmd)	set_bit(CMD_close, &(cmd)->flags)
#define cmd_close(cmd)	test_bit(CMD_close, &(cmd)->flags)

#define set_cmd_pending(cmd)	set_bit(CMD_pending, &(cmd)->flags)
#define clear_cmd_pending(cmd)	clear_bit(CMD_pending, &(cmd)->flags)
#define cmd_pending(cmd)	test_bit(CMD_pending, &(cmd)->flags)

/* We still use 'IET' id. Maybe someday, we get own id. */

#define VENDOR_ID	"IET"
#define PRODUCT_ID	"VIRTUAL-DISK"
#define PRODUCT_REV	"0"

#define show_param(param)\
{\
	eprintk("%d %d %d %d %d %d %d %d %d %d %d %d %d %d %d\n",\
		(param)->initial_r2t,\
		(param)->immediate_data,\
		(param)->max_connections,\
		(param)->max_recv_data_length,\
		(param)->max_xmit_data_length,\
		(param)->max_burst_length,\
		(param)->first_burst_length,\
		(param)->default_wait_time,\
		(param)->default_retain_time,\
		(param)->max_outstanding_r2t,\
		(param)->data_pdu_inorder,\
		(param)->data_sequence_inorder,\
		(param)->error_recovery_level,\
		(param)->header_digest,\
		(param)->data_digest);\
}

#undef dprintk

#undef DEBUG_ISTGT

#ifdef DEBUG_ISTGT
#define dprintk eprintk
#else
#define dprintk(fmt, args...)
#endif

#endif	/* __ISCSI_H__ */
