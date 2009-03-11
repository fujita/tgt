#ifndef TGTADM_H
#define TGTADM_H

#define TGT_IPC_NAMESPACE	"/tmp/.TGT_IPC_ABSTRACT_NAMESPACE"
#define TGT_LLD_NAME_LEN	64

#include "tgtadm_error.h"

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
	uint32_t device_type;
	uint32_t ac_dir;
	uint32_t pack;
};

struct tgtadm_rsp {
	uint32_t err;
	uint32_t len;
};

#endif
