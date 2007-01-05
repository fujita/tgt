#ifndef __TARGET_H__
#define __TARGET_H__

#define BITS_PER_LONG (ULONG_MAX == 0xFFFFFFFFUL ? 32 : 64)
#include <linux/hash.h>

/* better if we can include the followings in kernel header files. */
#define	MSG_SIMPLE_TAG	0x20
#define	MSG_HEAD_TAG	0x21
#define	MSG_ORDERED_TAG	0x22

#define	MAX_NR_HOST		1024

#define	HASH_ORDER	4
#define	hashfn(val)	hash_long((unsigned long) (val), HASH_ORDER)

struct acl_entry {
	char *address;
	struct list_head aclent_list;
};

struct tgt_account {
	int out_aid;
	int nr_inaccount;
	int max_inaccount;
	int *in_aids;
};

struct mgmt_req {
	uint64_t mid;
	int busy;
	int function;
};

struct target {
	char *name;

	int tid;
	int lid;

	enum scsi_target_iotype target_iotype;
	enum scsi_target_state target_state;

	struct list_head t_list;
	struct list_head t_hlist;

	struct list_head device_list;

	struct list_head cmd_hash_list[1 << HASH_ORDER];

	struct list_head it_nexus_list;

	struct tgt_cmd_queue cmd_queue;

	struct backedio_template *bdt;

	struct list_head acl_list;

	struct tgt_account account;
};

struct it_nexus {
	uint64_t nexus_id;

	struct target *nexus_target;

	/* the list of i_t_nexus belonging to a target */
	struct list_head nexus_siblings;
};

struct cmd {
	struct target *c_target;
	/* linked target->cmd_hash_list */
	struct list_head c_hlist;
	struct list_head qlist;

	uint64_t uaddr;
	uint32_t len;
	int mmapped;
	struct tgt_device *dev;
	unsigned long state;

	int hostno;
	uint32_t data_len;
	uint8_t scb[16];
	uint8_t lun[8];
	int attribute;
	uint64_t tag;
	int rw;
	struct mgmt_req *mreq;
};

enum {
	TGT_QUEUE_BLOCKED,
	TGT_QUEUE_DELETED,
};

enum {
	TGT_CMD_QUEUED,
	TGT_CMD_PROCESSED,
};

#define QUEUE_FNS(bit, name)						\
static inline void set_queue_##name(struct tgt_cmd_queue *q)		\
{									\
	(q)->state |= (1UL << TGT_QUEUE_##bit);				\
}									\
static inline void clear_queue_##name(struct tgt_cmd_queue *q)		\
{									\
	(q)->state &= ~(1UL << TGT_QUEUE_##bit);			\
}									\
static inline int queue_##name(const struct tgt_cmd_queue *q)		\
{									\
	return ((q)->state & (1UL << TGT_QUEUE_##bit));			\
}

static inline int queue_active(const struct tgt_cmd_queue *q)		\
{									\
	return ((q)->active_cmd);					\
}

QUEUE_FNS(BLOCKED, blocked)
QUEUE_FNS(DELETED, deleted)

#define CMD_FNS(bit, name)						\
static inline void set_cmd_##name(struct cmd *c)			\
{									\
	(c)->state |= (1UL << TGT_CMD_##bit);				\
}									\
static inline void clear_cmd_##name(struct cmd *c)			\
{									\
	(c)->state &= ~(1UL << TGT_CMD_##bit);				\
}									\
static inline int cmd_##name(const struct cmd *c)			\
{									\
	return ((c)->state & (1UL << TGT_CMD_##bit));			\
}

CMD_FNS(QUEUED, queued)
CMD_FNS(PROCESSED, processed)

#endif
