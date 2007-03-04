#ifndef TGTADM_H
#define TGTADM_H

#define TGT_IPC_NAMESPACE	"TGT_IPC_ABSTRACT_NAMESPACE"
#define TGT_LLD_NAME_LEN	64

enum tgtadm_errno {
	TGTADM_SUCCESS,
	TGTADM_UNKNOWN_ERR,
	TGTADM_NOMEM,
	TGTADM_NO_DRIVER,
	TGTADM_NO_TARGET,

	TGTADM_NO_LUN,
	TGTADM_NO_SESSION,
	TGTADM_NO_CONNECTION,
	TGTADM_TARGET_EXIST,
	TGTADM_LUN_EXIST,

	TGTADM_ACL_EXIST,
	TGTADM_USER_EXIST,
	TGTADM_NO_USER,
	TGTADM_TOO_MANY_USER,
	TGTADM_INVALID_REQUEST,

	TGTADM_OUTACCOUNT_EXIST,
	TGTADM_TARGET_ACTIVE,
	TGTADM_LUN_ACTIVE,
	TGTADM_UNSUPPORTED_OPERATION,
	TGTADM_UNKNOWN_PARAM,
};

enum tgtadm_op {
	OP_NEW,
	OP_DELETE,
	OP_SHOW,
	OP_BIND,
	OP_UNBIND,
	OP_UPDATE,
};

enum tgtadm_mode {
	MODE_SYSTEM,
	MODE_TARGET,
	MODE_DEVICE,

	MODE_SESSION,
	MODE_CONNECTION,
	MODE_ACCOUNT,
};

/* backing store type */
enum tgtadm_lu_bs_type {
	LU_BS_FILE,
	LU_BS_RAW, /* pass through */
};

enum tgtadm_account_dir {
	ACCOUNT_TYPE_INCOMING,
	ACCOUNT_TYPE_OUTGOING,
};

struct tgtadm_req {
	enum tgtadm_mode mode;
	enum tgtadm_op op;
	char lld[TGT_LLD_NAME_LEN];
	uint32_t len;
	int32_t tid;
	uint64_t sid;
	uint64_t lun;
	uint32_t cid;
	uint32_t host_no;
	uint32_t target_type;
	uint32_t bs_type;
	uint32_t ac_dir;
	uint32_t pack;
};

struct tgtadm_rsp {
	uint32_t err;
	uint32_t len;
};

#endif
