extern int ibmvio_target_create(struct target *);

extern uint64_t scsi_lun_to_int(uint8_t *p);

struct tgt_driver ibmvio = {
	.name			= "ibmvio",
	.use_kernel		= 1,
	.scsi_get_lun		= scsi_lun_to_int,
	.target_create		= ibmvio_target_create,
	.cmd_end_notify		= kspace_send_cmd_res,
	.mgmt_end_notify	= kspace_send_tsk_mgmt_res,
	.default_bdt		= &mmap_bdt,
};
