extern int scsi_inquiry(int host_no, struct scsi_cmd *cmd, void *key);
extern int scsi_report_luns(int host_no, struct scsi_cmd *cmd, void *key);

extern uint64_t scsi_lun_to_int(uint8_t *p);

struct tgt_driver ibmvio = {
	.name			= "ibmvio",
	.use_kernel		= 1,
	.scsi_get_lun		= scsi_lun_to_int,
	.scsi_report_luns	= scsi_report_luns,
	.scsi_inquiry		= scsi_inquiry,
	.cmd_end_notify		= kspace_send_cmd_res,
	.mgmt_end_notify	= kspace_send_tsk_mgmt_res,
	.default_bdt		= &mmap_bdt,
};
