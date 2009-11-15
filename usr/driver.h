#ifndef __DRIVER_H__
#define __DRIVER_H__

struct tgt_driver {
	const char *name;
	int use_kernel;

	int (*init)(int, char *);
	void (*exit)(void);

	int (*target_create)(struct target *);
	void (*target_destroy)(int);

	int (*lu_create)(struct scsi_lu *);

	int (*update)(int, int, int ,uint64_t, uint64_t, uint32_t, char *);
	int (*show)(int, int, uint64_t, uint32_t, uint64_t, char *, int);

	uint64_t (*scsi_get_lun)(uint8_t *);

	int (*cmd_end_notify)(uint64_t nid, int result, struct scsi_cmd *);
	int (*mgmt_end_notify)(struct mgmt_req *);

	int (*transportid)(int, uint64_t, char *, int);

	const char *default_bst;
};

extern struct tgt_driver *tgt_drivers[];
extern int get_driver_index(char *name);
extern int register_driver(struct tgt_driver *drv);

#endif /* __DRIVER_H__ */
