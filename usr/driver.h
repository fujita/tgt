extern struct backedio_template mmap_bdt, aio_bdt, sg_bdt, xen_bdt;

struct tgt_driver {
	const char *name;
	int use_kernel;

	int (*init) (int);

	int (*target_create) (int, char *);
	int (*target_destroy) (int);
	int (*target_update) (int, char *);

	int (*show) (int, int, uint64_t, uint32_t, uint64_t, char *, int);

	uint64_t (*scsi_get_lun)(uint8_t *);
	int (*scsi_report_luns)(struct list_head *, uint8_t *, uint8_t *,
				uint8_t *, int *);
	int (*scsi_inquiry)(struct tgt_device *, int, uint8_t *, uint8_t *,
			    uint8_t *, int *);
	int (*cmd_end_notify)(uint64_t nid, int result, struct scsi_cmd *);
	int (*mgmt_end_notify)(uint64_t nid, uint64_t mid, int result);

	struct backedio_template *default_bdt;
};

extern struct tgt_driver *tgt_drivers[];
extern int get_driver_index(char *name);

