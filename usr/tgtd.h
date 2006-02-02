#ifndef __TARGET_DAEMON_H
#define __TARGET_DAEMON_H

#include "log.h"
#include "dl.h"

#define	TGT_INVALID_DEV_ID	~0ULL

/* temporarily */
#define	POLLS_PER_DRV	32
extern int nl_fd;
extern struct pollfd *poll_array;

extern int target_thread_create(int *fd);

extern int nl_init(void);
extern void nl_event_handle(struct driver_info *, int fd);
extern int nl_cmd_call(int fd, int type, char *sbuf, int slen, char *rbuf, int rlen);
extern int nl_start(int fd);
extern int __nl_write(int fd, int type, char *data, int len);
extern int __nl_read(int fd, void *data, int size, int flags);

extern int ipc_open(void);
extern void ipc_event_handle(struct driver_info *, int fd);
extern void pipe_event_handle(int fd);

extern int tgt_device_init(void);
extern int tgt_device_create(int tid, uint64_t lun, int dfd);
extern int tgt_device_destroy(int tid, uint64_t lun);

extern uint64_t scsi_get_devid(uint8_t *pdu);
extern int scsi_cmd_process(int tid, uint8_t *pdu, int *len,
			    uint32_t datalen, unsigned long *uaddr, uint8_t *rw,
			    uint8_t *try_map, uint64_t *offset, uint64_t lun);
extern int scsi_cmd_done(int do_munmap, int do_free, uint64_t uaddr, int len);

#endif
