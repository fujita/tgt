#ifndef __TARGET_DAEMON_H
#define __TARGET_DAEMON_H

#include "log.h"

#define	SCSI_ID_LEN	24

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

	struct list_head d_hlist;
	struct list_head d_list;

	struct tgt_cmd_queue cmd_queue;
};

struct backedio_operations {
	void * (*cmd_buffer_alloc)(int devio, uint32_t datalen);
	int (*cmd_prepare)(struct tgt_device *dev, uint32_t datalen,
			   unsigned long *uaddr, uint64_t offset);
	int (*cmd_done) (int do_munmap, int do_free, uint64_t uaddr, int len);
};

extern int kreq_init(int *fd);
extern void kern_event_handler(int, void *data);

extern int ipc_init(int *fd);
extern void mgmt_event_handler(int accept_fd, void *data);

extern int tgt_device_create(int tid, uint64_t lun, char *path);
extern int tgt_device_destroy(int tid, uint64_t lun);
extern int tgt_target_create(int tid);
extern int tgt_target_destroy(int tid);
extern int tgt_target_bind(int tid, int host_no, int lid);

typedef void (event_handler_t)(int fd, void *data);
extern int tgt_event_add(int fd, int events, event_handler_t handler, void *data);
extern void tgt_event_del(int fd);

typedef int (cmd_end_t)(int host_no, int len, int result, int rw, uint64_t addr,
			 uint64_t tag);
typedef int (mgmt_end_t)(int host_no, uint64_t mid, int result);
extern int target_cmd_queue(int host_no, uint8_t *scb, uint8_t *lun,
			    uint32_t data_len, int attribute, uint64_t tag,
			    cmd_end_t *cmd_end);
extern void target_cmd_done(int host_no, uint64_t tag);
extern void target_mgmt_request(int host_no, int req_id, int function,
				uint8_t *lun, uint64_t tag, mgmt_end_t *mgmt_end);

extern uint64_t scsi_get_devid(int lid, uint8_t *pdu);
extern int scsi_cmd_perform(int lid, int host_no, uint8_t *pdu, int *len,
			    uint32_t datalen, unsigned long *uaddr, uint8_t *rw,
			    uint8_t *try_map, uint64_t *offset, uint8_t *lun,
			    struct tgt_device *dev, struct list_head *dev_list);

extern int sense_data_build(uint8_t *data, uint8_t res_code, uint8_t key,
			    uint8_t ascode, uint8_t ascodeq);

#endif
