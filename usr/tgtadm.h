#ifndef TGTADM_H
#define TGTADM_H

#define TGT_IPC_NAMESPACE	"TGT_IPC_ABSTRACT_NAMESPACE"
#define TGT_LLD_NAME_LEN	64

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

struct tgtadm_req {
	enum tgtadm_mode mode;
	enum tgtadm_op op;
	uint32_t len;

	int32_t tid;
	uint64_t sid;
	uint32_t cid;
	uint64_t lun;
	uint32_t aid;
	char lld[TGT_LLD_NAME_LEN];
	uint32_t host_no;
	uint64_t data[0];
} __attribute__ ((aligned (sizeof(uint64_t))));

struct tgtadm_res {
	uint32_t err;
	uint32_t len;
	uint64_t data[0];
} __attribute__ ((aligned (sizeof(uint64_t))));;

#endif
