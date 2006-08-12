#ifndef __TARGET_DAEMON_H
#define __TARGET_DAEMON_H

#include "log.h"
#include <scsi/scsi_tgt_if.h>

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

extern int kreq_init(int *fd);
extern int kreq_recv(void);
extern int kreq_send(struct tgt_event *ev);

extern int ipc_init(int *fd);
extern void ipc_event_handle(int accept_fd);

extern void kreq_exec(struct tgt_event *ev);
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
