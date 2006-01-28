#ifndef __DL_H
#define __DL_H

#define	MAX_DL_HANDLES	16

struct driver_info {
	char *name;
	char *proto;
	void *dl;
	void *pdl;
};

extern struct driver_info dlinfo[MAX_DL_HANDLES];

extern int dl_init(struct driver_info *);
extern struct pollfd * dl_poll_init(struct driver_info *, int *nr);

extern void *dl_poll_init_fn(struct driver_info *, int idx);
extern void *dl_poll_fn(struct driver_info *, int idx);
extern void *dl_ipc_fn(struct driver_info *, int typeid);
extern void *dl_event_fn(struct driver_info *, int tid, int typeid);
extern void *dl_proto_cmd_process(struct driver_info *, int tid, int typeid);
extern void *dl_proto_get_devid(struct driver_info *, int tid, int typeid);
extern void *dl_cmd_done_fn(struct driver_info *, int typeid);
extern char *typeid_to_name(struct driver_info *, int typeid);

#endif
