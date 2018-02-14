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

#include "bs_hyc.h"

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
			op = UNKNOWN;
			goto out;
		}
		op = WRITE_SAME_OP;
		break;
	case SYNCHRONIZE_CACHE:
	case SYNCHRONIZE_CACHE_16:
	default:
		eprintf("skipped cmd: %p op: %x\n", cmdp, scsi_op);
		op = UNKNOWN;
	}
out:
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
	case UNKNOWN:
		assert(0);
	}
	return 0;
}

struct hyc_cmd *hyc_cmd_alloc(struct bs_hyc_info *infop, struct scsi_cmd *cmdp,
	io_type_t op)
{
	struct hyc_cmd *hcmdp = NULL;

	hcmdp = calloc(1, sizeof(*hcmdp));
	if (!hcmdp) {
		return NULL;
	}

	DLL_INIT(&hcmdp->list);

	hcmdp->cmdp = cmdp;
	hcmdp->infop = infop;
	hcmdp->op = op;

	return hcmdp;
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

static int bs_hyc_cmd_submit(struct scsi_cmd *cmdp)
{
	struct scsi_lu     *lup = NULL;
	struct bs_hyc_info *infop = NULL;
	io_type_t           op;
	size_t              length;
	uint64_t            offset;
	char               *bufp = NULL;
	struct hyc_cmd     *hcmdp = NULL;
	RequestID           reqid = kInvalidRequestID;

	lup = cmdp->dev;
	infop = BS_HYC_I(lup);

	assert(infop->vmdk != kInvalidVmdkHandle);

	op = scsi_cmd_operation(cmdp);
	if (op == UNKNOWN) {
		return -EINVAL;
	}

	hcmdp = hyc_cmd_alloc(infop, cmdp, op);
	if (!hcmdp) {
		return -ENOMEM;
	}

	offset = scsi_cmd_offset(cmdp);
	length = scsi_cmd_length(cmdp);

	bufp = scsi_cmd_buffer(cmdp);
	set_cmd_async(cmdp);

	pthread_mutex_lock(&infop->lock);
	DLL_ADD(&infop->sched_cmd_list, &hcmdp->list);
	pthread_mutex_unlock(&infop->lock);

	switch (op) {
	case READ:
		reqid = ScheduleRead(infop->vmdk, hcmdp, bufp, length, offset);
		break;
	case WRITE:
		reqid = ScheduleWrite(infop->vmdk, hcmdp, bufp, length, offset);
		break;
	case WRITE_SAME_OP:
		/** TODO */
	case UNKNOWN:
	default:
		assert(0);
	}

	/* If we got reqid, set it in hyc_cmd */
	if (reqid != kInvalidRequestID) {
		hcmdp->reqid = reqid;
	} else {
		eprintf("request submission got err invalid request\n");
		pthread_mutex_lock(&infop->lock);
		DLL_REM(&hcmdp->list);
		pthread_mutex_unlock(&infop->lock);
		target_cmd_io_done(hcmdp->cmdp, SAM_STAT_CHECK_CONDITION);
		free(hcmdp);
	}

	return 0;
}

static void bs_hyc_handle_completion(int fd, int events, void *datap)
{
	struct bs_hyc_info   *infop;
	uint64_t              c;
	struct RequestResult *resultsp = NULL;
	bool                  has_more = true; /** True for the first cmd completion */
	int                   rc;
	int                   i;

	assert(datap);
	infop = datap;

	resultsp = infop->request_resultsp;

	rc = eventfd_read(fd, &c);
	assert(rc == 0);

	while (has_more == true) {
		uint32_t nr_results = GetCompleteRequests(infop->vmdk, resultsp,
						infop->nr_results, &has_more);
		pthread_mutex_lock(&infop->lock);
		/* Process completed request commands */
		for (i = 0; i < nr_results; ++i) {
			struct hyc_cmd *hcmdp = (struct hyc_cmd *)resultsp[i].privatep;
			assert(hcmdp);

			assert(resultsp[i].result == 0);
			target_cmd_io_done(hcmdp->cmdp, SAM_STAT_GOOD);

			DLL_REM(&hcmdp->list);
			free(hcmdp);
		}
		pthread_mutex_unlock(&infop->lock);
		memset(resultsp, 0, sizeof (*resultsp) * infop->nr_results);
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

	assert(infop->vmdk != kInvalidVmdkHandle);
	rc = SetVmdkEventFd(infop->vmdk, infop->done_eventfd);
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
	int                 rc;
	char               *p;
	char               *vmdkid = NULL;
	char               *vmid = NULL;

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

	assert(lup->tgt);

	infop->vmid = vmid;
	infop->vmdkid = vmdkid;
	infop->vmdk = GetVmdkHandle(vmdkid);
	assert(infop->vmdk != kInvalidVmdkHandle);

	rc = pthread_mutex_init(&infop->lock, NULL);
	assert(rc == 0);

	DLL_INIT(&infop->sched_cmd_list);

	/** TODO: Use a symbolic const over here */
	infop->nr_results = 32;
	infop->request_resultsp = calloc(infop->nr_results,
					sizeof(*infop->request_resultsp));
	if (!infop->request_resultsp) {
		eprintf("hyc bs init failed\n");
		e = TGTADM_NOMEM;
		free(vmid);
		free(vmdkid);
		pthread_mutex_destroy(&infop->lock);
	}

	return e;
}

static void bs_hyc_exit(struct scsi_lu *lup)
{
	struct bs_hyc_info *infop = BS_HYC_I(lup);
	int    rc;


	assert(infop);
	assert(DLL_ISEMPTY(&infop->sched_cmd_list));

	free(infop->request_resultsp);
	free(infop->vmid);
	free(infop->vmdkid);

	rc = pthread_mutex_destroy(&infop->lock);

	assert(rc == 0);
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
