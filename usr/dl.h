#ifndef __DL_H
#define __DL_H

#define	MAX_DL_HANDLES	16

#define	DL_FN_POLL_INIT		0
#define	DL_FN_POLL_EVENT	1
#define	DL_FN_IPC_MGMT		2
#define	DL_FN_SCSI_INQUIRY	3
#define	DL_FN_SCSI_REPORT_LUN	4
#define	DL_FN_SCSI_LUN_TO_INT	5
#define	DL_FN_END		6

struct driver_info {
	char *name;
	void *dl;
	void *fn[DL_FN_END];
};

extern struct driver_info dlinfo[];

extern int dl_init(struct driver_info *);
extern void *dl_fn(struct driver_info *, int, int);
#endif
