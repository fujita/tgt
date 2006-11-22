extern int iscsi_init(int);
extern int iscsi_target_create(int, char *);
extern int iscsi_target_destroy(int);
extern int iscsi_target_show(int mode, int tid, uint64_t sid, uint32_t cid,
			     uint64_t lun, char *buf, int rest);
extern int iscsi_target_update(int, char *);
extern int iscsi_mgmt_account(uint32_t op, int tid, uint32_t uid, char *param,
			      char *buf, int len);
extern int iscsi_scsi_cmd_done(int host_no, int len, int result, int rw,
			       uint64_t addr, uint64_t tag);
extern int iscsi_tm_done(int host_no, uint64_t mid, int result);

struct tgt_driver iscsi = {
	.name			= "iscsi",
	.use_kernel		= 0,
	.init			= iscsi_init,
	.target_create		= iscsi_target_create,
	.target_destroy		= iscsi_target_destroy,
	.target_update		= iscsi_target_update,
	.show			= iscsi_target_show,
	.account		= iscsi_mgmt_account,
	.cmd_end_notify		= iscsi_scsi_cmd_done,
	.mgmt_end_notify	= iscsi_tm_done,
	.default_bdt		= &aio_bdt,
};
