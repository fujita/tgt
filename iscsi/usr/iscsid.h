/*
 * Copyright (C) 2002-2003 Ardis Technolgies <roman@ardistech.com>
 *
 * Released under the terms of the GNU GPL v2.0.
 */

#ifndef ISCSID_H
#define ISCSID_H

#include <search.h>
#include <sys/types.h>

#include "types.h"
#include "iet_u.h"
#include "param.h"
#include "misc.h"
#include "log.h"
#include <iscsi_proto.h>

#define sid64(isid, tsih)					\
({								\
	(uint64_t) isid[0] <<  0 | (uint64_t) isid[1] <<  8 |	\
	(uint64_t) isid[2] << 16 | (uint64_t) isid[3] << 24 |	\
	(uint64_t) isid[4] << 32 | (uint64_t) isid[5] << 40 |	\
	(uint64_t) tsih << 48;					\
})

#define PROC_SESSION	"/proc/net/iet/session"

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
	struct qelem slist;

	char *initiator;
	struct target *target;
	uint8_t isid[6];
	uint16_t tsih;

	int conn_cnt;
};

struct connection {
	int state;
	int iostate;
	int fd;

	struct session *session;

	u32 tid;
	struct iscsi_param session_param[session_key_last];

	char *initiator;
	uint8_t isid[6];
	uint16_t tsih;
	u16 cid;
	u16 pad;
	int session_type;
	int auth_method;

	u32 stat_sn;
	u32 exp_stat_sn;

	u32 cmd_sn;
	u32 exp_cmd_sn;
	u32 max_cmd_sn;

	struct PDU req;
	void *req_buffer;
	struct PDU rsp;
	void *rsp_buffer;
	unsigned char *buffer;
	int rwsize;

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

#define BHS_SIZE		48

#define INCOMING_BUFSIZE	8192

struct target {
	struct qelem tlist;

	struct qelem sessions_list;

	u32 tid;
	char name[ISCSI_NAME_LEN];
	char *alias;

	int max_nr_sessions;
	int nr_sessions;
};

/* chap.c */
extern int cmnd_exec_auth_chap(struct connection *conn);

/* conn.c */
extern struct connection *conn_alloc(void);
extern void conn_free(struct connection *conn);
extern int conn_test(struct connection *conn);
extern void conn_take_fd(struct connection *conn, int fd);
extern void conn_read_pdu(struct connection *conn);
extern void conn_write_pdu(struct connection *conn);
extern void conn_free_pdu(struct connection *conn);

/* iscsid.c */
extern int iscsi_debug;

extern int cmnd_execute(struct connection *conn);
extern void cmnd_finish(struct connection *conn);
extern char *text_key_find(struct connection *conn, char *searchKey);
extern void text_key_add(struct connection *conn, char *key, char *value);

/* session.c */
extern struct session *session_find_name(u32 tid, const char *iname, uint8_t *isid);
extern struct session *session_find_id(u32 tid, u64 sid);
extern void session_create(struct connection *conn);
extern void session_remove(struct session *session);

/* target.c */
extern int target_add(int *tid, char *name);
extern int target_del(int tid);
extern int target_find_by_name(const char *name, u32 *tid);
struct target * target_find_by_id(u32);
extern void target_list_build(struct connection *, char *, char *);

/* ctldev.c */
struct iscsi_kernel_interface {
	int (*lunit_create) (u32 tid, u32 lun, char *args);
	int (*lunit_destroy) (u32 tid, u32 lun);
	int (*param_get) (u32, u64, struct iscsi_param *);
	int (*param_set) (u32, u64, int, u32, struct iscsi_param *);
	int (*target_create) (int *, char *);
	int (*target_destroy) (u32);
	int (*session_create) (u32, u64, u32, u32, char *);
	int (*session_destroy) (u32, u64);
	int (*conn_create) (u32, u64, u32, u32, u32, int, u32, u32);
	int (*conn_destroy) (u32 tid, u64 sid, u32 cid);
};

extern struct iscsi_kernel_interface *ki;

/* param.c */
int param_index_by_name(char *name, struct iscsi_key *keys);

/* #define log_error(fmt, args...)						\ */
/* do {									\ */
/* } while (0) */

/* #define log_warning(fmt, args...)					\ */
/* do {									\ */
/* } while (0) */

/* #define log_debug(fmt, args...)						\ */
/* do {									\ */
/* } while (0) */

#define log_pdu(x, y)							\
do {									\
} while (0)

#endif	/* ISCSID_H */
