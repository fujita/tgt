#ifndef __BS_HYC_H__
#define __BS_HYC_H__


/** This structure is per LUN/VMDK */
struct bs_hyc_info {
	struct scsi_lu *lup;
	char           *vmid;
	char           *vmdkid;
};

#endif

