extern int scsi_inquiry(struct tgt_device *dev, int host_no, uint8_t *lun_buf,
			uint8_t *scb, uint8_t *data, int *len);
extern int scsi_report_luns(struct list_head *dev_list, uint8_t *lun_buf,
			    uint8_t *scb, uint8_t *p, int *len);

extern uint64_t scsi_lun_to_int(uint8_t *p);

struct tgt_driver ibmvio = {
	.name			= "ibmvio",
	.scsi_get_lun		= scsi_lun_to_int,
	.scsi_report_luns	= scsi_report_luns,
	.scsi_inquiry		= scsi_inquiry,
	.cmd_end_notify		= kspace_send_cmd_res,
	.mgtm_end_notify	= kspace_send_tsk_mgmt_res,
	.bdt			= &mmap_bdt,
};
