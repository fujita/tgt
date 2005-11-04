#ifndef __TARGET_DAEMON_H
#define __TARGET_DAEMON_H

#include "log.h"

extern int nl_fd;

extern int nl_open(void);
extern void nl_event_handle(int fd);
extern int nl_cmd_call(int fd, int type, char *sbuf, int slen, char *rbuf, int rlen);

extern int ipc_open(void);
extern void ipc_event_handle(int fd);

#endif
