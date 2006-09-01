/*
 * Copyright (C) 2002-2003 Ardis Technolgies <roman@ardistech.com>
 *
 * Released under the terms of the GNU GPL v2.0.
 */

#ifndef ISCSID_H
#define ISCSID_H

#include <stdint.h>
#include <inttypes.h>
#include <linux/types.h>
#include <asm/byteorder.h>

#include "list.h"
#include "param.h"
#include "log.h"

#include <scsi/iscsi_if.h>
#include <scsi/iscsi_proto.h>

#define cpu_to_be16(x)	__cpu_to_be16(x)
#define cpu_to_be32(x)	__cpu_to_be32(x)
#define be16_to_cpu(x)	__be16_to_cpu(x)
#define be32_to_cpu(x)	__be32_to_cpu(x)

#define ISCSI_NAME_LEN 256
#define ISTGT_NAMESPACE "ISTGT_ABSTRACT_NAMESPACE"

#define DIGEST_ALL		(DIGEST_NONE | DIGEST_CRC32C)
#define DIGEST_NONE		(1 << 0)
#define DIGEST_CRC32C           (1 << 1)

#define sid64(isid, tsih)					\
({								\
	(uint64_t) isid[0] <<  0 | (uint64_t) isid[1] <<  8 |	\
	(uint64_t) isid[2] << 16 | (uint64_t) isid[3] << 24 |	\
	(uint64_t) isid[4] << 32 | (uint64_t) isid[5] << 40 |	\
	(uint64_t) tsih << 48;					\
})

struct PDU {
	struct iscsi_hdr bhs;
	void *ahs;
	unsigned int ahssize;
	void *data;
	unsigned int datasize;
};

#define KEY_STATE_START		0
#define KEY_STATE_REQUEST	1
#define KEY_STATE_DONE		2

struct session {
	/* linked to target->sessions_list */
	struct list_head slist;

	/* linked to sessions_list */
	struct list_head hlist;

	char *initiator;
	struct target *target;
	uint8_t isid[6];
	uint16_t tsih;

	/* links all connections (conn->clist) */
	struct list_head conn_list;
	int conn_cnt;

	/* links all tasks (task->c_hlist) */
	struct list_head cmd_list;

	/* links pending tasks (task->c_list) */
	struct list_head pending_cmd_list;

	uint32_t exp_cmd_sn;
};

struct iscsi_task {
	struct iscsi_hdr req;
	struct iscsi_hdr rsp;

	uint64_t tag;
	struct connection *conn;

	/* linked to session->cmd_list */
	struct list_head c_hlist;

	/* linked to conn->tx_clist or session->cmd_pending_list */
	struct list_head c_list;

	unsigned long flags;

	uint64_t addr;
	int result;
	int len;
	int rw;

	int offset;
	int data_sn;

	int r2t_count;
	int unsol_count;
	int exp_r2tsn;

	void *c_buffer;
};

struct connection {
	int state;
	int rx_iostate;
	int tx_iostate;
	int fd;

	struct list_head clist;
	struct session *session;

	int tid;
	struct param session_param[ISCSI_PARAM_MAX];

	char *initiator;
	uint8_t isid[6];
	uint16_t tsih;
	uint16_t cid;
	int session_type;
	int auth_method;

	uint32_t stat_sn;
	uint32_t exp_stat_sn;

	uint32_t cmd_sn;
	uint32_t exp_cmd_sn;
	uint32_t max_cmd_sn;

	struct PDU req;
	void *req_buffer;
	struct PDU rsp;
	void *rsp_buffer;
	unsigned char *rx_buffer;
	unsigned char *tx_buffer;
	int rx_size;
	int tx_size;

	struct iscsi_task *rx_task;
	struct iscsi_task *tx_task;

	struct list_head tx_clist;

	int auth_state;
	union {
		struct {
			int digest_alg;
			int id;
			int challenge_size;
			unsigned char *challenge;
		} chap;
	} auth;
};

#define IOSTATE_FREE		0
#define IOSTATE_READ_BHS	1
#define IOSTATE_READ_AHS_DATA	2
#define IOSTATE_WRITE_BHS	3
#define IOSTATE_WRITE_AHS	4
#define IOSTATE_WRITE_DATA	5

#define STATE_FREE		0
#define STATE_SECURITY		1
#define STATE_SECURITY_AUTH	2
#define STATE_SECURITY_DONE	3
#define STATE_SECURITY_LOGIN	4
#define STATE_SECURITY_FULL	5
#define STATE_LOGIN		6
#define STATE_LOGIN_FULL	7
#define STATE_FULL		8
#define STATE_KERNEL		9
#define STATE_CLOSE		10
#define STATE_EXIT		11
#define STATE_SCSI		12

#define AUTH_STATE_START	0
#define AUTH_STATE_CHALLENGE	1

/* don't touch these */
#define AUTH_DIR_INCOMING       0
#define AUTH_DIR_OUTGOING       1

#define SESSION_NORMAL		0
#define SESSION_DISCOVERY	1
#define AUTH_UNKNOWN		-1
#define AUTH_NONE		0
#define AUTH_CHAP		1
#define DIGEST_UNKNOWN		-1

#define BHS_SIZE		sizeof(struct iscsi_hdr)

#define INCOMING_BUFSIZE	8192

struct target {
	struct list_head tlist;

	struct list_head sessions_list;

	int tid;
	char name[ISCSI_NAME_LEN];
	char *alias;

	int max_nr_sessions;
	int nr_sessions;
};

enum task_flags {
	TASK_pending,
};

#define set_task_pending(t)	((t)->flags |= (1 << TASK_pending))
#define clear_task_pending(t)	((t)->flags &= ~(1 << TASK_pending))
#define task_pending(t)		((t)->flags & (1 << TASK_pending))

/* chap.c */
extern int cmnd_exec_auth_chap(struct connection *conn);

/* conn.c */
extern struct connection *conn_alloc(void);
extern void conn_free(struct connection *conn);
extern struct connection * conn_find(struct session *session, uint32_t cid);
extern int conn_take_fd(struct connection *conn, int fd);
extern void conn_read_pdu(struct connection *conn);
extern void conn_write_pdu(struct connection *conn);
extern void conn_add_to_session(struct connection *conn, struct session *session);

/* iscsid.c */
extern char *text_key_find(struct connection *conn, char *searchKey);
extern void text_key_add(struct connection *conn, char *key, char *value);

/* session.c */
extern struct session *session_find_name(int tid, const char *iname, uint8_t *isid);
extern int session_create(struct connection *conn);
extern void session_destroy(struct session *session);
extern struct session *session_lookup(uint16_t tsih);

/* target.c */
extern int target_find_by_name(const char *name, int *tid);
struct target * target_find_by_id(int tid);
extern void target_list_build(struct connection *, char *, char *);

/* param.c */
int param_index_by_name(char *name, struct iscsi_key *keys);

#endif	/* ISCSID_H */
