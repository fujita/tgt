#ifndef __TARGET_DAEMON_H
#define __TARGET_DAEMON_H

#include "log.h"

#define SCSI_ID_LEN	24
#define SCSI_SN_LEN	8

#define VENDOR_ID	"IET"

#define TID_SHIFT 32
#define NID_MASK ((1ULL << TID_SHIFT) - 1)
#define NID64(tid, nid) ((uint64_t) tid << TID_SHIFT | nid)
#define NID2TID(nid) (nid >> TID_SHIFT)

#define _TAB1 "    "
#define _TAB2 _TAB1 _TAB1
#define _TAB3 _TAB1 _TAB1 _TAB1
#define _TAB4 _TAB2 _TAB2

enum scsi_target_state {
	SCSI_TARGET_OFFLINE = 1,
	SCSI_TARGET_RUNNING,
};

enum scsi_lu_state {
	SCSI_LU_OFFLINE = 1,
	SCSI_LU_RUNNING,
};

struct tgt_cmd_queue {
	int active_cmd;
	unsigned long state;
	struct list_head queue;
};

struct scsi_lu {
	int fd;
	uint64_t addr; /* persistent mapped address */
	uint64_t size;
	uint64_t lun;
	char scsi_id[SCSI_ID_LEN];
	char scsi_sn[SCSI_SN_LEN];
	char *path;

	/* the list of devices belonging to a target */
	struct list_head device_siblings;

	struct tgt_cmd_queue cmd_queue;

	enum scsi_lu_state lu_state;

	uint64_t reserve_id;

	/* TODO: needs a structure for lots of device parameters */
	uint8_t d_sense;
};

struct scsi_cmd {
	struct target *c_target;
	/* linked target->cmd_hash_list */
	struct list_head c_hlist;
	struct list_head qlist;

	uint64_t uaddr;
	uint32_t len;
	int mmapped;
	struct scsi_lu *dev;
	unsigned long state;

	uint64_t cmd_nexus_id;
	uint32_t data_len;
	uint64_t offset;
	uint8_t *scb;
	int scb_len;
	uint8_t lun[8];
	int attribute;
	uint64_t tag;
	uint8_t rw;
	int async;
	int result;
	struct mgmt_req *mreq;

#define SCSI_SENSE_BUFFERSIZE	252
	unsigned char sense_buffer[SCSI_SENSE_BUFFERSIZE];
	int sense_len;

	/* workaround */
	struct list_head bs_list;
};

struct backingstore_template {
	int bs_datasize;
	int (*bs_open)(struct scsi_lu *dev, char *path, int *fd, uint64_t *size);
	void (*bs_close)(struct scsi_lu *dev);
	int (*bs_cmd_submit)(struct scsi_cmd *cmd);
	int (*bs_cmd_done) (struct scsi_cmd *cmd);
};

#ifdef USE_KERNEL
extern int kreq_init(void);
#else
static inline int kreq_init(void)	\
{					\
	return 0;			\
}
#endif

struct device_type_operations {
	int (*cmd_perform)(int host_no, struct scsi_cmd *cmd);
};

struct device_type_template {
	unsigned char type;
	char *name;
	char *pid;

	void (*device_init)(struct scsi_lu *dev);

	struct device_type_operations ops[256];
};

extern int kspace_send_tsk_mgmt_res(uint64_t nid, uint64_t mid, int result);
extern int kspace_send_cmd_res(uint64_t nid, int result, struct scsi_cmd *);

extern int ipc_init(void);
extern int tgt_device_create(int tid, uint64_t lun, char *args);
extern int tgt_device_destroy(int tid, uint64_t lun);
extern int tgt_device_update(int tid, uint64_t dev_id, char *name);
extern int device_reserve(uint64_t nid, uint64_t lun, uint64_t reserve_id);
extern int device_release(uint64_t nid, uint64_t lun, uint64_t reserve_id, int force);
extern int device_reserved(uint64_t nid, uint64_t lun, uint64_t reserve_id);

extern int tgt_target_create(int lld, int tid, char *args, int t_type);
extern int tgt_target_destroy(int tid);
extern int tgt_target_bind(int tid, int host_no, int lld);
extern char *tgt_targetname(int tid);
extern int tgt_target_show_all(char *buf, int rest);

typedef void (event_handler_t)(int fd, int events, void *data);
extern int tgt_event_add(int fd, int events, event_handler_t handler, void *data);
extern void tgt_event_del(int fd);
extern int tgt_event_modify(int fd, int events);
extern int target_cmd_queue(struct scsi_cmd *cmd);
extern void target_cmd_done(struct scsi_cmd *cmd);
struct scsi_cmd *target_cmd_lookup(uint64_t nid, uint64_t tag);
extern void target_mgmt_request(uint64_t nid, uint64_t req_id, int function,
				uint8_t *lun, uint64_t tag);

extern void target_cmd_io_done(struct scsi_cmd *cmd, int result);

extern uint64_t scsi_get_devid(int lid, uint8_t *pdu);
extern int scsi_cmd_perform(int host_no, struct scsi_cmd *cmd);
extern void sense_data_build(struct scsi_cmd *cmd, uint8_t key, uint8_t asc,
			     uint8_t asq);
extern uint64_t scsi_rw_offset(uint8_t *scb);

extern enum scsi_target_state tgt_get_target_state(int tid);
extern int tgt_set_target_state(int tid, char *str);

extern int acl_add(int tid, char *address);
extern void acl_del(int tid, char *address);
extern char *acl_get(int tid, int idx);

extern int account_lookup(int tid, int type, char *user, int ulen, char *password, int plen);
extern int account_add(char *user, char *password);
extern void account_del(char *user);
extern int account_ctl(int tid, int type, char *user, int bind);
extern int account_show(char *buf, int rest);
extern int account_available(int tid, int dir);

extern int it_nexus_create(int tid, char *info, uint64_t *nid);
extern int it_nexus_destroy(uint64_t nid);

/* crap. kill this after done it_nexus kernel code */
extern int it_nexus_to_host_no(uint64_t nid);
extern uint64_t host_no_to_it_nexus(int host_no);

#endif
