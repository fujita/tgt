#ifndef __TGTXEN_H__
#define __TGTXEN_H__

extern int xen_init(void);

struct tgt_driver xen = {
	.name			= "xen",
	.use_kernel		= 1,
	.init			= xen_init,
	.cmd_end_notify		= kspace_send_cmd_res,
	.mgmt_end_notify	= kspace_send_tsk_mgmt_res,
	.default_bst		= &xen_bst,
};

#endif
