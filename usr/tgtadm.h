#ifndef TGTADM_H
#define TGTADM_H

#define TGT_IPC_NAMESPACE	"TGT_IPC_ABSTRACT_NAMESPACE"
#define TGT_LLD_NAME_LEN	64

enum tgtadm_op {
	OP_NEW,
	OP_DELETE,
	OP_SHOW,
	OP_BIND,
};

enum tgtadm_mode {
	MODE_SYSTEM,
	MODE_TARGET,
	MODE_DEVICE,

	MODE_SESSION,
	MODE_CONNECTION,
	MODE_USER,
};

struct tgtadm_req {
	enum tgtadm_mode mode;
	enum tgtadm_op op;

	int tid;
	uint64_t sid;
	int cid;
	uint64_t lun;
	char lld[TGT_LLD_NAME_LEN];
	int host_no;
	unsigned long addr;
};

struct tgtadm_res {
	int err;
	unsigned long addr;
};

#endif
