#ifndef __DL_H
#define __DL_H

#define	MAX_DL_HANDLES	16

struct driver_info {
	char *name;
	void *dl;
};

extern struct driver_info dlinfo[];

extern int dl_init(struct driver_info *);
extern struct pollfd * dl_poll_init(struct driver_info *, int *nr);

extern void *dl_poll_init_fn(struct driver_info *, int idx);
extern void *dl_poll_fn(struct driver_info *, int idx);
extern void *dl_ipc_fn(struct driver_info *, int typeid);
extern void *dl_event_fn(struct driver_info *, int tid, int typeid);

#endif
