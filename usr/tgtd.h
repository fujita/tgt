#ifndef __SCSI_TARGET_DAEMON_H
#define __SCSI_TARGET_DAEMON_H

#include "log.h"

extern int nl_fd;
extern void *dl_handles[];

extern int nl_open(void);
extern void nl_event_handle(int fd);
extern int nl_cmd_call(int fd, int type, char *data, int size, char *rbuf);

extern int ipc_open(void);
extern void ipc_event_handle(int fd);

extern int scsi_cmd_process(int tid, uint64_t lun, uint8_t *scb,
			    uint8_t *data, int *len);
#endif
