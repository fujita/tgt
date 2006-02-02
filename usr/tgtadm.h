#ifndef TGTADM_H
#define TGTADM_H

#define TGT_IPC_NAMESPACE "TGT_IPC_ABSTRACT_NAMESPACE"

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
	int typeid;
	int host_no;
	unsigned long addr;
};

struct tgtadm_res {
	int err;
	unsigned long addr;
};

extern int ktarget_destroy(int tid);
extern int ktarget_create(int typeid);
extern int tgt_mgmt(char *sbuf, char *rbuf);

#endif
