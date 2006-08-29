extern struct backedio_template mmap_bdt;

struct tgt_driver {
	const char *name;

	int (*init) (int *);

	int (*target_create) (int, char *);
	int (*target_destroy) (int);

	uint64_t (*scsi_get_lun)(uint8_t *);
	int (*scsi_report_luns)(struct list_head *, uint8_t *, uint8_t *,
				uint8_t *, int *);
	int (*scsi_inquiry)(struct tgt_device *, int, uint8_t *, uint8_t *,
			    uint8_t *, int *);
	int (*cmd_end_notify)(int host_no, int len, int result, int rw, uint64_t addr,
			      uint64_t tag);
	int (*mgmt_end_notify)(int host_no, uint64_t mid, int result);

	int enable;
	int pfd_index;

	struct backedio_template *bdt;
};

extern struct tgt_driver *tgt_drivers[];
extern int get_driver_index(char *name);

