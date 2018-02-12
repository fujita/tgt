#ifndef __BS_HYC_H__
#define __BS_HYC_H__

#include "TgtTypes.h"
#include "dll.h"

typedef enum {
	READ,
	WRITE,
	/* Appending with *_OP, since just WRITE_SAME conflicts with scsi.h */
	WRITE_SAME_OP,
	UNKNOWN,
} io_type_t;

/** This structure is per LUN/VMDK */
struct bs_hyc_info {
	dll_t                  sched_cmd_list;
	struct scsi_lu        *lup;
	char                  *vmid;
	char                  *vmdkid;
	VmdkHandle             vmdk;
	int                    done_eventfd;
	struct RequestResult  *request_resultsp;
	uint32_t               nr_results;
	pthread_mutex_t        lock;
};

struct hyc_cmd {
	dll_t               list;
	struct scsi_cmd    *cmdp;
	struct bs_hyc_info *infop;
	int                 result;
	io_type_t           op;
	RequestID           reqid;
	bool                done;
};

#endif

