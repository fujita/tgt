#ifndef _TGT_PRIV_H
#define _TGT_PRIV_H

struct tgt_target;

extern struct tgt_target *target_find(int tid);
extern int tgt_device_create(int tid, uint64_t dev_id, char *device_type,
			     int fd, unsigned long dflags);
extern int tgt_device_destroy(int tid, uint64_t dev_id);
extern int uspace_cmd_done(int tid, uint64_t dev_id, uint64_t cid, void *data,
			   int result, uint32_t len);
extern void tgt_nl_exit(void);
extern int tgt_nl_init(void);
extern int tgt_sysfs_init(void);
extern void tgt_sysfs_exit(void);

#endif
