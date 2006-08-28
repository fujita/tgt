extern struct backedio_operations mmap_bdops;

struct tgt_driver {
	const char *name;

	int (*init) (int *);

	int (*target_create) (int, char *);
	int (*target_destroy) (int);
	int (*target_bind)(int);

	uint64_t (*scsi_get_lun)(uint8_t *);
	int (*scsi_report_luns)(struct list_head *, uint8_t *, uint8_t *,
				uint8_t *, int *);
	int (*scsi_inquiry)(struct tgt_device *, int, uint8_t *, uint8_t *,
			    uint8_t *, int *);
	int enable;
	int pfd_index;

	struct backedio_operations *io_ops;
};

extern struct tgt_driver *tgt_drivers[];
extern int get_driver_index(char *name);

