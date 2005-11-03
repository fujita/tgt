#ifndef TGTADM_H
#define TGTADM_H

#define TGT_IPC_NAMESPACE "TGT_IPC_ABSTRACT_NAMESPACE"

#define	SET_TARGET	(1 << 0)
#define	SET_SESSION	(1 << 1)
#define	SET_CONNECTION	(1 << 2)
#define	SET_DEVICE	(1 << 3)
#define	SET_USER	(1 << 4)

enum tgtadm_op {
	OP_NEW,
	OP_DELETE,
	OP_UPDATE,
	OP_SHOW,
};

struct tgtadm_req {
	int typeid;
	int op;
	uint32_t set;

	int tid;
	uint64_t sid;
	int cid;
	uint64_t lun;
};

struct tgtadm_res {
	int err;
};

#endif
