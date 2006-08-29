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

	unsigned long bddata[0] __attribute__ ((aligned (sizeof(unsigned long))));
};

struct backedio_template {
	struct tgt_device *(*bd_open)(char *path, int *fd, uint64_t *size);
	void (*bd_close)(struct tgt_device *dev);
	void *(*bd_cmd_buffer_alloc)(int devio, uint32_t datalen);
	int (*bd_cmd_submit)(struct tgt_device *dev, int rw, uint32_t datalen,
			     unsigned long *uaddr, uint64_t offset);
	int (*bd_cmd_done) (int do_munmap, int do_free, uint64_t uaddr, int len);
};

extern int kreq_init(void);
extern int kspace_send_tsk_mgmt_res(int host_no, uint64_t mid, int result);
extern int kspace_send_cmd_res(int host_no, int len, int result,
			       int rw, uint64_t addr, uint64_t tag);

extern int ipc_init(void);

extern int tgt_device_create(int tid, uint64_t lun, char *path);
extern int tgt_device_destroy(int tid, uint64_t lun);
extern int tgt_target_create(int tid);
extern int tgt_target_destroy(int tid);
extern int tgt_target_bind(int tid, int host_no, int lid);

typedef void (event_handler_t)(int fd, void *data);
extern int tgt_event_add(int fd, int events, event_handler_t handler, void *data);
extern void tgt_event_del(int fd);

extern int target_cmd_queue(int host_no, uint8_t *scb, uint8_t *lun,
			    uint32_t data_len, int attribute, uint64_t tag);
extern void target_cmd_done(int host_no, uint64_t tag);
extern void target_mgmt_request(int host_no, int req_id, int function,
				uint8_t *lun, uint64_t tag);

extern uint64_t scsi_get_devid(int lid, uint8_t *pdu);
extern int scsi_cmd_perform(int lid, int host_no, uint8_t *pdu, int *len,
			    uint32_t datalen, unsigned long *uaddr, uint8_t *rw,
			    uint8_t *try_map, uint64_t *offset, uint8_t *lun,
			    struct tgt_device *dev, struct list_head *dev_list);

extern int sense_data_build(uint8_t *data, uint8_t res_code, uint8_t key,
			    uint8_t ascode, uint8_t ascodeq);

#endif
