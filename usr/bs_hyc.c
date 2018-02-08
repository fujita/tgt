/*
 * hyc I/O backing store routine
 *
 * Copyright (C) 2008 Alexander Nezhinsky <nezhinsky@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/epoll.h>
#include <assert.h>

#include "list.h"
#include "tgtd.h"
#include "scsi.h"
#include "target.h"
#include "util.h"

#include "bs_hyc.h"

static inline struct bs_hyc_info *BS_HYC_I(struct scsi_lu *lu)
{
	return (struct bs_hyc_info *) ((char *)lu + sizeof (*lu));
}

static int bs_hyc_cmd_submit(struct scsi_cmd *cmd)
{
	scsi_set_result(cmd, SAM_STAT_GOOD);
	return 0;
}

static void bs_hyc_handle_completion(int fd, int events, void *datap)
{
	//struct bs_hyc_info *infop;
	//struct scsi_cmd    *cmdp = NULL;

	//infop = datap;

	/** TODO: For all the scsi_cmds, call target_cmd_io_done() */
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

static void bs_hyc_close(struct scsi_lu *lu)
{

}

static tgtadm_err bs_hyc_init(struct scsi_lu *lup, char *bsoptsp)
{
	struct bs_hyc_info *infop = BS_HYC_I(lup);
	tgtadm_err          e;

	memset(infop, 0, sizeof(*infop));

	infop->lup = lup;

	assert(lup->tgt);
	assert(lup->tgt->vmid);

	infop->vmid = lup->tgt->vmid;
	infop->vmdkid = lup->vmdkid;

	e = TGTADM_SUCCESS;
	return e;
}

static void bs_hyc_exit(struct scsi_lu *lup)
{

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
