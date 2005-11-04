#ifndef TGTADM_H
#define TGTADM_H

#define TGT_IPC_NAMESPACE "TGT_IPC_ABSTRACT_NAMESPACE"

enum tgtadm_op {
	OP_NEW,
	OP_DELETE,
	OP_UPDATE,
	OP_SHOW,
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
	int typeid;

	enum tgtadm_mode mode;
	enum tgtadm_op op;

	int tid;
	uint64_t sid;
	int cid;
	uint64_t lun;
};

struct tgtadm_res {
	int err;
};

extern int tgt_mgmt(char *sbuf, char *rbuf);
extern int ktarget_destroy(int tid);
extern int ktarget_create(int typeid);
extern int kdevice_destroy(int tid, uint64_t devid);
extern int kdevice_create(int tid, uint64_t devid, char *path, char *devtype);
extern void kdevice_create_parser(char *args, char **path, char **devtype);

#endif
