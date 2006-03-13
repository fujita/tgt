#ifndef __TARGET_DAEMON_H
#define __TARGET_DAEMON_H

#include "log.h"
#include "dl.h"
#include "util.h"

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
	struct list_head dlist;

	struct tgt_cmd_queue cmd_queue;
};

/* makeshift */
#define	POLLS_PER_DRV	32

extern int nl_init(void);
extern int __nl_write(int fd, int type, char *data, int len);
extern int __nl_read(int fd, void *data, int size, int flags);
void nl_event_handle(int nl_fd);

extern int ipc_open(void);
extern void ipc_event_handle(struct driver_info *, int fd);

extern int tgt_device_init(void);
extern int tgt_device_create(int tid, uint64_t lun, char *path);
extern int tgt_device_destroy(int tid, uint64_t lun);
extern int tgt_target_create(int tid);
extern int tgt_target_destroy(int tid);
extern int tgt_target_bind(int tid, int host_no, int lid);

extern uint64_t scsi_get_devid(int lid, uint8_t *pdu);
extern int scsi_cmd_perform(int lid, int host_no, uint8_t *pdu, int *len,
			    uint32_t datalen, unsigned long *uaddr, uint8_t *rw,
			    uint8_t *try_map, uint64_t *offset, uint8_t *lun,
			    struct tgt_device *dev, struct list_head *dev_list);

extern int sense_data_build(uint8_t *data, uint8_t res_code, uint8_t key,
			    uint8_t ascode, uint8_t ascodeq);
#endif
