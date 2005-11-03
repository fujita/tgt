#ifndef __DL_H
#define __DL_H

#define	MAX_DL_HANDLES	16

extern int dl_init(void);
extern void dl_config_load(void);
extern struct pollfd * dl_poll_init(int *nr);

extern void *dl_poll_init_fn(int idx);
extern void *dl_poll_fn(int idx);
extern void *dl_ipc_fn(int typeid);
extern void *dl_event_fn(int tid, int typeid);
extern void *dl_proto_cmd_process(int tid, int typeid);

#endif
