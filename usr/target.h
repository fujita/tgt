#ifndef __TARGET_H__
#define __TARGET_H__

#include <limits.h>
#define BITS_PER_LONG (ULONG_MAX == 0xFFFFFFFFUL ? 32 : 64)
#include "hash.h"

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

struct target {
	char *name;

	int tid;
	int lid;

	enum scsi_target_state target_state;

	struct list_head target_siblings;

	struct list_head device_list;

	struct list_head it_nexus_list;

	struct tgt_cmd_queue cmd_queue;

	struct backingstore_template *bst;

	struct list_head acl_list;

	struct tgt_account account;

	/* we don't use a pointer because a lld could change this. */
	struct device_type_template dev_type_template;
};

struct it_nexus {
	uint64_t itn_id;

	struct list_head cmd_hash_list[1 << HASH_ORDER];

	struct target *nexus_target;

	/* the list of i_t_nexus belonging to a target */
	struct list_head nexus_siblings;

	/* dirty hack for IBMVIO */
	int host_no;

	/* only used for show operation */
	char *info;
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
static inline void set_cmd_##name(struct scsi_cmd *c)			\
{									\
	(c)->state |= (1UL << TGT_CMD_##bit);				\
}									\
static inline void clear_cmd_##name(struct scsi_cmd *c)			\
{									\
	(c)->state &= ~(1UL << TGT_CMD_##bit);				\
}									\
static inline int cmd_##name(const struct scsi_cmd *c)			\
{									\
	return ((c)->state & (1UL << TGT_CMD_##bit));			\
}

CMD_FNS(QUEUED, queued)
CMD_FNS(PROCESSED, processed)

#endif
