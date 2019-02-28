/*
 * hyc I/O backing store routine
 */

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/epoll.h>
#include <assert.h>
#include <stdbool.h>
#include <pthread.h>

#include "list.h"
#include "tgtd.h"
#include "scsi.h"
#include "target.h"
#include "util.h"
#include "parser.h"
#include "iscsi/iscsid.h"

#include "bs_hyc.h"

#include "TgtTypes.h"
#include "TgtInterface.h"

static inline struct bs_hyc_info *BS_HYC_I(struct scsi_lu *lu)
{
	return (struct bs_hyc_info *) ((char *)lu + sizeof (*lu));
}

io_type_t scsi_cmd_operation(struct scsi_cmd *cmdp)
{
	unsigned int        scsi_op = (unsigned int) cmdp->scb[0];
	io_type_t           op = UNKNOWN;

	switch (scsi_op) {
	case UNMAP:
		return TRUNCATE;
	case WRITE_6:
	case WRITE_10:
	case WRITE_12:
	case WRITE_16:
		op = WRITE;
		break;
	case READ_6:
	case READ_10:
	case READ_12:
	case READ_16:
		op = READ;
		break;
	case WRITE_SAME:
	case WRITE_SAME_16:
		/** WRITE_SAME used to punch a hole in file */
		if (cmdp->scb[1] & 0x08) {
			eprintf("Unmap with WRITE_SAME for hyc backend is not"
				" supported yet.\n");
		}
		op = WRITE_SAME_OP;
		break;
	case SYNCHRONIZE_CACHE:
	case SYNCHRONIZE_CACHE_16:
	default:
		eprintf("skipped cmd: %p op: %x\n", cmdp, scsi_op);
		op = UNKNOWN;
	}
	return op;
}

static uint64_t scsi_cmd_offset(struct scsi_cmd *cmdp)
{
	return cmdp->offset;
}

static uint32_t scsi_cmd_length(struct scsi_cmd *cmdp)
{
	switch (scsi_cmd_operation(cmdp)) {
	case READ:
		return scsi_get_in_length(cmdp);
	case WRITE_SAME_OP:
	case WRITE:
		return scsi_get_out_transfer_len(cmdp);
	default:
		assert(0);
	}
	return 0;
}

static char *scsi_cmd_buffer(struct scsi_cmd *cmdp)
{
	switch (scsi_cmd_operation(cmdp)) {
	default:
		assert(0);
		return NULL;
	case READ:
		return scsi_get_in_buffer(cmdp);
	case WRITE:
	case WRITE_SAME_OP:
		return scsi_get_out_buffer(cmdp);
	}
}

static int bs_hyc_unmap(struct bs_hyc_info* infop, struct scsi_lu* lup,
		struct scsi_cmd* cmdp)
{
	size_t length;
	char* bufp;

	if (!lup->attrs.thinprovisioning) {
		return -1;
	}

	length = scsi_get_out_length(cmdp);
	bufp = scsi_get_out_buffer(cmdp);
	if (length < 0 || bufp == NULL) {
		return 0;
	}

	length -= 8;
	bufp += 8;
	set_cmd_async(cmdp);
	return HycScheduleTruncate(infop->vmdk_handle, cmdp, bufp, length);
}

static int bs_hyc_cmd_submit(struct scsi_cmd *cmdp)
{
	struct scsi_lu     *lup = NULL;
	struct bs_hyc_info *infop = NULL;
	io_type_t           op;
	size_t              length;
	uint64_t            offset;
	char               *bufp = NULL;
	RequestID           reqid = kInvalidRequestID;

	lup = cmdp->dev;
	infop = BS_HYC_I(lup);

	assert(infop->vmdk_handle != kInvalidVmdkHandle);

	op = scsi_cmd_operation(cmdp);
	switch (op) {
	default:
		break;
	case TRUNCATE:
		return bs_hyc_unmap(infop, lup, cmdp);
	case WRITE_SAME_OP:
		return -1;
	case UNKNOWN:
		return 0;
	}

	offset = scsi_cmd_offset(cmdp);
	length = scsi_cmd_length(cmdp);

	/*
	 * Simply returing from top for zero size IOs, we may need to handle
	 * it later for the barrier IOs
	 */

	if(op == WRITE) {
		if (!length) {
			eprintf("Zero size write IO, returning from top :%lu\n", length);
			return 0;
		}
	} else if(op == READ) {
		if (!length) {
			eprintf("Zero size read IO, returning from top :%lu\n", length);
			return 0;
		}
	}

	bufp = scsi_cmd_buffer(cmdp);
	set_cmd_async(cmdp);

	switch (op) {
	case READ:
		reqid = HycScheduleRead(infop->vmdk_handle, cmdp, bufp, length, offset);
		break;
	case WRITE:
		reqid = HycScheduleWrite(infop->vmdk_handle, cmdp, bufp, length, offset);
		break;
	case WRITE_SAME_OP:
	case UNKNOWN:
	default:
		assert(0);
	}

	/* If we got reqid, set it in hyc_cmd */
	if (hyc_unlikely(reqid == kInvalidRequestID)) {
		eprintf("request submission got error invalid request" 
			" size: %lu offset : %"PRIu64" opcode :%u\n", 
			length, offset, (unsigned int) cmdp->scb[0]);
		/*
		 *  TODO: This change requires further investigation we have seen core dumps
		 *  with this change. Keeping it as todo, investigation will be done later.
		 *  Reverting to the original path.
		 */

		//clear_cmd_async(cmdp);
		target_cmd_io_done(cmdp, SAM_STAT_CHECK_CONDITION);
		return -EINVAL;
	}

	return 0;
}

static void bs_hyc_handle_completion(int fd, int events, void *datap)
{
	struct bs_hyc_info *infop;
	struct RequestResult *resultsp;
	bool has_more;

	assert(datap);
	infop = datap;
	resultsp = infop->request_resultsp;
	has_more = true;

	while (has_more == true) {
		uint32_t nr_results = HycGetCompleteRequests(infop->vmdk_handle,
			resultsp, infop->nr_results, &has_more);

		/* Process completed request commands */
		for (uint32_t i = 0; i < nr_results; ++i) {
			struct scsi_cmd *cmdp = (struct scsi_cmd *) resultsp[i].privatep;
			assert(cmdp);

			if (resultsp[i].result ==0) {
				target_cmd_io_done(cmdp, SAM_STAT_GOOD);
			} else {
				eprintf("retry for vmid:%s, vmdkid:%s, path:%s, op_type:%d, offset:%lu, length:%u\n",
					infop->vmid, infop->vmdkid, infop->lup->path,
					scsi_cmd_operation(cmdp), scsi_cmd_offset(cmdp),
					scsi_cmd_length(cmdp));
				sense_data_build(cmdp, MEDIUM_ERROR, 0);
				target_cmd_io_done(cmdp, SAM_STAT_CHECK_CONDITION);
			}
		}
		memset(resultsp, 0, sizeof(*resultsp) * nr_results);

		if (has_more == false) {
			eventfd_t c = 0;
			int rc = eventfd_read(fd, &c);
			if (hyc_unlikely(rc < 0)) {
				assert(errno == EAGAIN || errno == EWOULDBLOCK);
			}
			has_more = c != 0;
		}
	}
}

static int bs_hyc_open(struct scsi_lu *lup, char *pathp,
			int *fdp, uint64_t *sizep)
{
	struct bs_hyc_info *infop = BS_HYC_I(lup);
	int                 rc = 0;
	int                 ffd = -1;
	int                 efd = -1;
	uint32_t            blksize;

	ffd = backed_file_open(pathp, O_RDWR | O_LARGEFILE | O_DIRECT, sizep,
		&blksize);
	if (ffd < 0) {
		eprintf("Failed to open %s, for tgt: %d, lun: %"PRId64 ", %m\n",
			pathp, infop->lup->tgt->tid, infop->lup->lun);
		rc = ffd;
		goto error;
	}

	/** TODO: Validate blksize, whether its what we need or not */
	if (!lup->attrs.no_auto_lbppbe) {
		update_lbppbe(lup, blksize);
	}

	efd = eventfd(0, O_NONBLOCK);
	if (efd < 0) {
		rc = errno;
		goto error;
	}

	rc = tgt_event_add(efd, EPOLLIN, bs_hyc_handle_completion, infop);
	if (rc < 0) {
		goto error;
	}

	infop->done_eventfd = efd;

	rc = HycOpenVmdk(infop->vmid, infop->vmdkid, *sizep, lup->blk_shift,
		infop->done_eventfd, &infop->vmdk_handle);
	if (rc < 0) {
		goto error;
	}

	*fdp = ffd;
	return 0;
error:
	if (efd >= 0) {
		close(efd);
		efd = -1;
	}
	if (ffd >= 0) {
		close(ffd);
		ffd = -1;
	}
	return rc;
}

static void bs_hyc_close(struct scsi_lu *lup)
{
	struct bs_hyc_info *infop = BS_HYC_I(lup);

	assert(infop);
	assert(infop->done_eventfd >= 0);

	tgt_event_del(infop->done_eventfd);
	HycCloseVmdk(infop->vmdk_handle);
	close(infop->done_eventfd);
	infop->done_eventfd = -1;

	close(lup->fd);
}

enum {
	Opt_vmid, Opt_vmdkid, Opt_err,
};

static match_table_t bs_hyc_opts = {
	{Opt_vmid, "vmid=%s"},
	{Opt_vmdkid, "vmdkid=%s"},
	{Opt_err, NULL},
};

static tgtadm_err bs_hyc_init(struct scsi_lu *lup, char *bsoptsp)
{
	struct bs_hyc_info *infop = BS_HYC_I(lup);
	tgtadm_err          e = TGTADM_SUCCESS;
	char               *p;
	char               *vmdkid = NULL;
	char               *vmid = NULL;

	assert(lup->tgt);

	eprintf("bsopts:%s\n", bsoptsp);
	while((p = strsep(&bsoptsp, ":")) != NULL) {
		substring_t args[MAX_OPT_ARGS];
		int token;
		if (!*p)
			continue;
		token = match_token(p, bs_hyc_opts, args);
		switch (token) {
		case Opt_vmid:
			vmid = match_strdup(&args[0]);
			break;
		case Opt_vmdkid:
			vmdkid = match_strdup(&args[0]);
			break;
		default:
			break;
		}
	}
	if (!vmid || !vmdkid) {
		eprintf("hyc bst needs both vmid: %s & vmdkid: %s as bsopts\n",
			vmid, vmdkid);
		return TGTADM_INVALID_REQUEST;
	}

	memset(infop, 0, sizeof(*infop));

	infop->lup = lup;
	infop->vmid = vmid;
	infop->vmdkid = vmdkid;
	infop->nr_results = 32;
	infop->request_resultsp = calloc(infop->nr_results,
		sizeof(*infop->request_resultsp));
	if (!infop->request_resultsp) {
		eprintf("hyc bs init failed\n");
		e = TGTADM_NOMEM;
		free(vmid);
		free(vmdkid);
	}
	return e;
}

static void bs_hyc_exit(struct scsi_lu *lup)
{
	struct bs_hyc_info *infop = BS_HYC_I(lup);

	assert(infop);

	free(infop->request_resultsp);
	free(infop->vmid);
	free(infop->vmdkid);
}

static struct backingstore_template hyc_bst = {
	.bs_name		= "hyc",
	.bs_datasize		= sizeof(struct bs_hyc_info),
	.bs_init		= bs_hyc_init,
	.bs_exit		= bs_hyc_exit,
	.bs_open		= bs_hyc_open,
	.bs_close		= bs_hyc_close,
	.bs_cmd_submit		= bs_hyc_cmd_submit,
};

__attribute__((constructor)) static void bs_hyc_constructor(void)
{
	register_backingstore_template(&hyc_bst);
}
