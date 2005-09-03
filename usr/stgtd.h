#ifndef __SCSI_TARGET_DAEMON_H
#define __SCSI_TARGET_DAEMON_H

#define eprintf(fmt, args...)						\
do {									\
	fprintf(stderr, "%s(%d) " fmt, __FUNCTION__, __LINE__, args);	\
} while (0)


#define dprintf(fmt, args...)						\
do {									\
	if ((stgtd_debug)) {						\
		eprintf(fmt, args);					\
	}								\
} while (0)

extern uint32_t stgtd_debug;
extern int nl_fd;

extern int nl_open(void);
extern void nl_event_handle(int fd);
extern int nl_cmnd_call(int fd, int type, char *data, int size, int *res);

extern int ipc_open(void);
extern void ipc_event_handle(int fd);

extern int scsi_cmnd_process(int tid, uint32_t lun, uint8_t *scb,
			     uint8_t *data, int *len);

#endif
