extern int iscsi_init(void);
extern int iscsi_target_create(int, char *);
extern int iscsi_target_destroy(int);
extern int iscsi_scsi_cmd_done(int host_no, int len, int result, int rw,
			       uint64_t addr, uint64_t tag);

struct tgt_driver iscsi = {
	.name		= "iscsi",
	.init		= iscsi_init,
	.target_create	= iscsi_target_create,
	.target_destroy	= iscsi_target_destroy,
	.cmd_end_notify	= iscsi_scsi_cmd_done,
	.bdt		= &aio_bdt,
};
