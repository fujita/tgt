#ifndef _IET_ADM_H
#define _IET_ADM_H

#define IETADM_NAMESPACE "IET_ABSTRACT_NAMESPACE"

struct msg_trgt {
	char name[ISCSI_NAME_LEN];
	char alias[ISCSI_NAME_LEN];

	u32 type;
	u32 session_partial;
	u32 target_partial;
	struct iscsi_param session_param[session_key_last];
	struct iscsi_param target_param[session_key_last];
};

struct msg_acnt {
	u32 auth_dir;
	char user[ISCSI_NAME_LEN];
	char pass[ISCSI_NAME_LEN];
};

struct msg_lunit {
	char args[ISCSI_ARGS_LEN];
};

enum ietadm_cmnd {
	C_TRGT_NEW,
	C_TRGT_DEL,
	C_TRGT_UPDATE,
	C_TRGT_SHOW,

	C_SESS_NEW,
	C_SESS_DEL,
	C_SESS_UPDATE,
	C_SESS_SHOW,

	C_CONN_NEW,
	C_CONN_DEL,
	C_CONN_UPDATE,
	C_CONN_SHOW,

	C_LUNIT_NEW,
	C_LUNIT_DEL,
	C_LUNIT_UPDATE,
	C_LUNIT_SHOW,

	C_ACCT_NEW,
	C_ACCT_DEL,
	C_ACCT_UPDATE,
	C_ACCT_SHOW,

	C_SYS_NEW,
	C_SYS_DEL,
	C_SYS_UPDATE,
	C_SYS_SHOW,
};

struct ietadm_req {
	enum ietadm_cmnd rcmnd;

	u32 tid;
	u64 sid;
	u32 cid;
	u32 lun;

	union {
		struct msg_trgt trgt;
		struct msg_acnt acnt;
		struct msg_lunit lunit;
	} u;
};

struct ietadm_rsp {
	int err;
};

#endif
