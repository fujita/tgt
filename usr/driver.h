extern struct backedio_template mmap_bdt, aio_bdt, sg_bdt;

struct tgt_driver {
	const char *name;
	int use_kernel;

	int (*init) (int);

	int (*target_create) (int, char *);
	int (*target_destroy) (int);
	int (*target_update) (int, char *);

	int (*show) (int, int, uint64_t, uint32_t, uint64_t, char *, int);
	int (*account) (uint32_t, int, uint32_t, char *, char *, int);

	uint64_t (*scsi_get_lun)(uint8_t *);
	int (*scsi_report_luns)(struct list_head *, uint8_t *, uint8_t *,
				uint8_t *, int *);
	int (*scsi_inquiry)(struct tgt_device *, int, uint8_t *, uint8_t *,
			    uint8_t *, int *);
	int (*cmd_end_notify)(int host_no, int len, int result, int rw, uint64_t addr,
			      uint64_t tag);
	int (*mgmt_end_notify)(int host_no, uint64_t mid, int result);

	struct backedio_template *default_bdt;
};

extern struct tgt_driver *tgt_drivers[];
extern int get_driver_index(char *name);

