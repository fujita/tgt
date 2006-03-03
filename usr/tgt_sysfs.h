#include <stdint.h>

#ifndef	__TGT_SYSFS_H
#define	__TGT_SYSFS_H

#define	TGT_LLD_SYSFSDIR	"/var/run/tgt_lld"
#define	TGT_TARGET_SYSFSDIR	"/var/run/tgt_target"


extern int tgt_target_dir_create(int tid);
extern int tgt_target_dir_delete(int tid);

extern int tgt_device_dir_create(int tid, uint64_t dev_id);
extern int tgt_device_dir_delete(int tid, uint64_t dev_id);

#endif
