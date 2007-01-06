#ifndef __TARGET_DAEMON_H
#define __TARGET_DAEMON_H

#include "log.h"

#define SCSI_ID_LEN	24
#define SCSI_SN_LEN	8

#define TID_SHIFT 32
#define NID_MASK ((1ULL << TID_SHIFT) - 1)
#define NID64(tid, nid) ((uint64_t) tid << TID_SHIFT | nid)
#define NID2TID(nid) (nid >> TID_SHIFT)

#define TAB1 "    "
#define TAB2 TAB1 TAB1
#define TAB3 TAB1 TAB1 TAB1
#define TAB4 TAB2 TAB2

enum scsi_target_iotype {
	SCSI_TARGET_FILEIO = 1,
	SCSI_TARGET_RAWIO,
};

enum scsi_target_state {
	SCSI_TARGET_SUSPENDED = 1,
	SCSI_TARGET_RUNNING,
};

struct tgt_cmd_queue {
	int active_cmd;
	unsigned long state;
	struct list_head queue;
};

struct tgt_device {
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

	uint64_t reserve_id;
};

typedef int (bkio_submit_t) (struct tgt_device *dev, uint8_t *scb,
			     int rw, uint32_t datalen, unsigned long *uaddr,
			     uint64_t offset, int *async, void *key);

struct backedio_template {
	int bd_datasize;
	int (*bd_open)(struct tgt_device *dev, char *path, int *fd, uint64_t *size);
	void (*bd_close)(struct tgt_device *dev);
	bkio_submit_t *bd_cmd_submit;
	int (*bd_cmd_done) (int do_munmap, int do_free, uint64_t uaddr, int len);
};

#ifdef USE_KERNEL
extern int kreq_init(void);
#else
static inline int kreq_init(void)	\
{					\
	return 0;			\
}
#endif

#ifndef USE_RAW
struct backedio_template sg_bdt;
#endif

extern int kspace_send_tsk_mgmt_res(uint64_t nid, uint64_t mid, int result);
extern int kspace_send_cmd_res(uint64_t nid, int len, int result,
			       int rw, uint64_t addr, uint64_t tag);
extern int ipc_init(void);
extern int tgt_device_create(int tid, uint64_t lun, char *args);
extern int tgt_device_destroy(int tid, uint64_t lun);
extern int tgt_device_update(int tid, uint64_t dev_id, char *name);
extern int device_reserve(uint64_t nid, uint64_t lun, uint64_t reserve_id);
extern int device_release(uint64_t nid, uint64_t lun, uint64_t reserve_id, int force);
extern int device_reserved(uint64_t nid, uint64_t lun, uint64_t reserve_id);

extern int tgt_target_create(int lld, int tid, char *args, int t_type, int bs_type);
extern int tgt_target_destroy(int tid);
extern int tgt_target_bind(int tid, int host_no, int lld);
extern char *tgt_targetname(int tid);
extern int tgt_target_show_all(char *buf, int rest);

typedef void (event_handler_t)(int fd, int events, void *data);
extern int tgt_event_add(int fd, int events, event_handler_t handler, void *data);
extern void tgt_event_del(int fd);
extern int tgt_event_modify(int fd, int events);

extern int target_cmd_queue(uint64_t nid, uint8_t *scb, uint8_t rw,
			    unsigned long uaddr,
			    uint8_t *lun, uint32_t data_len,
			    int attribute, uint64_t tag);
extern void target_cmd_done(uint64_t nid, uint64_t tag);
extern void target_mgmt_request(uint64_t nid, uint64_t req_id, int function,
				uint8_t *lun, uint64_t tag);

extern void target_cmd_io_done(void *key, int result);

extern uint64_t scsi_get_devid(int lid, uint8_t *pdu);
extern int scsi_cmd_perform(uint64_t nid, int lid, int host_no, uint8_t *pdu, int *len,
			    uint32_t datalen, unsigned long *uaddr, uint8_t *rw,
			    uint8_t *try_map, uint64_t *offset, uint8_t *lun,
			    struct tgt_device *dev, struct list_head *dev_list,
			    int *async, void *key, bkio_submit_t *submit);

extern int sense_data_build(uint8_t *data, uint8_t res_code, uint8_t key,
			    uint8_t ascode, uint8_t ascodeq);

extern enum scsi_target_state tgt_get_target_state(int tid);
extern int tgt_set_target_state(int tid, char *str);

extern int acl_add(int tid, char *address);
extern void acl_del(int tid, char *address);
extern char *acl_get(int tid, int idx);

extern int account_lookup(int tid, int type, char *user, char *password, int plen);
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
