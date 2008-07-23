#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <linux/if.h>

#include "list.h"
#include "log.h"
#include "util.h"
#include "tgtd.h"

#include "fc_types.h"
#include "fc_port.h"
#include "fc_event.h"
#include "fc_remote_port.h"
#include "fcdev.h"
#include "fc_frame.h"
#include "openfc_target.h"
#include "openfc_scst_pkt.h"
#include "fcs_state.h"
#include "fc_fcp.h"
#include "fc_encaps.h"
#include "fc_sess.h"

struct fc_scsi_pkt *openfc_alloc_scsi_pkt(void *arg)
{
	struct fc_scsi_pkt *sp;
	sp = zalloc(sizeof(*sp));
	if (sp) {
		sp->openfcp = (void *) arg;
		sp->state = OPENFC_SRB_INIT;
		sp->ref_cnt = 1;
	}
	return sp;
}

void openfct_send_xfer_rdy(struct fc_scsi_pkt *pkt)
{
	struct fc_seq  *sp = pkt->seq_ptr;
	struct fc_frame *fp;
	struct fc_data_desc *dd;

	fp = fc_frame_alloc(pkt->openfcp->fcs_port, sizeof(*dd));
	dd = fc_frame_payload_get(fp, sizeof(*dd));
	sp = fc_seq_start_next(sp);
	net32_put(&dd->dd_offset, 0);
	net32_put(&dd->dd_len, pkt->data_len);
	fc_seq_send_req(sp, fp, FC_RCTL_DD_DATA_DESC, FC_TYPE_FCP, 0);
}

static int openfct_cp_to_user(struct fc_scsi_pkt *fsp, uint offset,
			      void *buf, int len)
{
	struct scsi_cmd *scmd = &fsp->scmd;
	char *data = scsi_get_out_buffer(scmd);

	memcpy(data + offset, buf, len);

	return len;
}

void openfct_rcv_data(struct fc_seq *sp, struct fc_frame *fp, void *arg)
{
	struct openfchba_softc *hba;
	struct fc_scsi_pkt *pkt;
	struct fc_frame_header *fh;
	u_int		r_ctl;
	int		len;
	u_int32_t	offset;

	fh = fc_frame_header_get(fp);
	r_ctl = fh->fh_r_ctl;
	switch (r_ctl) {
	case FC_RCTL_DD_SOL_DATA:
		/* received data packet */
		pkt = (struct fc_scsi_pkt *) arg;
		hba = pkt->openfcp;
		offset = net32_get(&fh->fh_parm_offset);
		len = fp->fr_len - sizeof(*fh);
		if (pkt->xfer_len != offset) {
			goto out;
		}

		pkt->xfer_len += openfct_cp_to_user(pkt, offset,
						    fc_frame_payload_get(fp, 0),
						    len);
		dprintf("%x %d %d\n", net24_get(&fh->fh_f_ctl), len, offset);

		if (net24_get(&fh->fh_f_ctl) & FC_FC_SEQ_INIT) {
			if (pkt->xfer_len < pkt->bufflen) {
				pkt->t_state = OPENFC_STATE_NEED_DATA;
			} else
				pkt->t_state = OPENFC_CMD_DONE;

			/* FIXME */
			pkt->t_state = OPENFC_STATE_DATA_IN;
			target_cmd_queue(1, &pkt->scmd);
		}

		break;
	default:
		eprintf("unknown rctl \n");
	}
      out:
	fc_frame_free(fp);
}

void openfct_rcv_cmd(struct fc_seq *sp, struct fc_frame *fp, void *arg)
{
	struct openfchba_softc *hba;
	struct fc_scsi_pkt *pkt;
	struct fc_frame_header *fh;
	struct fcp_cmnd *fcmd;
	u_int		r_ctl;

	fh = fc_frame_header_get(fp);
	r_ctl = fh->fh_r_ctl;

	dprintf("%u\n", r_ctl);
	switch (r_ctl) {
	case FC_RCTL_DD_UNSOL_CMD:
		/* receved cmd */
		fc_seq_hold(sp);
		hba = (struct openfchba_softc *) arg;
		pkt = openfc_alloc_scsi_pkt(hba);
		pkt->cnt = 0;
		fcmd = fc_frame_payload_get(fp, sizeof(*fcmd));
		pkt->exid = net16_get(&fh->fh_ox_id);
		pkt->fcid = net24_get(&fh->fh_s_id);
		pkt->seq_ptr = sp;
		pkt->xfer_len = 0;
		pkt->data_len = net32_get(&fcmd->fc_dl);
		pkt->lun = net64_get((net64_t *) & fcmd->fc_lun);
		memcpy(pkt->lunp, fcmd->fc_lun, 8);
		memcpy(pkt->cdb, fcmd->fc_cdb, 16);

		fc_seq_set_recv(sp, openfct_rcv_data, (void *)pkt);
		openfct_process_scsi_cmd(hba, pkt, fcmd);
		break;
	default:
		eprintf("unknown rctl \n");
	}
	fc_frame_free(fp);
}

void openfc_scst_completion(void *arg)
{
	struct fc_scsi_pkt *pkt  = arg;
	struct scsi_cmd *scmd = &pkt->scmd;

	eprintf("pkt->cnt %u\n", pkt->cnt);

	if (!(--pkt->cnt)) {
		if (pkt->seq_ptr)
			fc_seq_exch_complete(pkt->seq_ptr);
		pkt->seq_ptr = NULL;

		if (!(pkt->flags & OPENFC_TMF_PKT))
			target_cmd_done(scmd);
		if (scsi_get_in_buffer(scmd))
			free(scsi_get_in_buffer(scmd));
		if (scsi_get_out_buffer(scmd))
			free(scsi_get_out_buffer(scmd));
		free(pkt);
	}
}

void openfct_scsi_send_tmf_rsp(struct fc_scsi_pkt *pkt, uint8_t rsp)
{
	struct fc_seq  *sp = pkt->seq_ptr;
	struct fc_frame *fp;
	struct fcp_resp *fc_rp;
	struct fcp_resp_ext *fc_exrp;
	struct fcp_resp_rsp_info *fc_rsp_info;
	unsigned int len;

	len = sizeof(*fc_rp) + sizeof(*fc_exrp) + sizeof(*fc_rsp_info);

	fp = fc_frame_alloc(pkt->openfcp->fcs_port, len);
	if (!fp)
		return;
	pkt->cnt = 1;
	fp->fr_destructor = openfc_scst_completion;
	fp->fr_arg = pkt;
	fc_rp = fc_frame_payload_get(fp, sizeof(*fc_rp));
	memset(fc_rp, 0, len);
	sp = fc_seq_start_next(sp);

	fc_rp->fr_flags = SS_RESPONSE_INFO_LEN_VALID;
	fc_exrp = (struct fcp_resp_ext *) (fc_rp + 1);
	net32_put(&fc_exrp->fr_rsp_len, sizeof(*fc_rsp_info));

	fc_rsp_info = (struct fcp_resp_rsp_info *) (fc_exrp + 1);
	fc_rsp_info->rsp_code = rsp;

	fc_seq_send_last(sp, fp, FC_RCTL_DD_CMD_STATUS, FC_TYPE_FCP);
}

void openfct_scsi_send_status(struct fc_scsi_pkt *pkt)
{
	struct fc_seq  *sp = pkt->seq_ptr;
	struct fc_frame *fp;
	struct fcp_resp *fc_rp;
	struct fcp_resp_ext *fc_exrp;
	uint8_t *bufp;
	u_int len;

	len = sizeof(*fc_rp);
	if (pkt->flags & OPENFC_SENSE_VALID)
		len = sizeof(*fc_exrp) + pkt->sense_buffer_len;
	fp = fc_frame_alloc(pkt->openfcp->fcs_port, len);
	if (!fp)
		return;
	pkt->cnt = 1;
	fp->fr_destructor = openfc_scst_completion;
	fp->fr_arg = pkt;
	fc_rp = fc_frame_payload_get(fp, sizeof(*fc_rp));
	memset(fc_rp, 0, len);
	sp = fc_seq_start_next(sp);
	net16_put((net16_t *) &fc_rp->fr_flags, pkt->rq_result);
	if (pkt->flags & OPENFC_SENSE_VALID) {
		fc_exrp = (struct fcp_resp_ext *) (fc_rp + 1);
		net32_put(&fc_exrp->fr_sns_len, pkt->sense_buffer_len);
		bufp = (uint8_t *) (fc_exrp + 1);
		memcpy(bufp, pkt->sense_buffer, pkt->sense_buffer_len);
	}
	fc_seq_send_last(sp, fp, FC_RCTL_DD_CMD_STATUS, FC_TYPE_FCP);
}

static void
openfc_scsi_send_data(struct fc_scsi_pkt *fsp, struct fc_seq *sp)
{
	struct fc_frame *fp = NULL;
	size_t offset = 0;
	size_t len;
	size_t		remaining;
	size_t		buf_offset;
	size_t		data_len;
	size_t		mfs;
	size_t		tlen;
	int		error;
	void		*data = NULL;
	void 		*page_addr;

	data_len = fsp->data_len;

	len = scsi_get_in_length(&fsp->scmd) - scsi_get_in_resid(&fsp->scmd);

	dprintf("%p %zu %d\n", fsp, data_len, scsi_get_in_resid(&fsp->scmd));
	len = min(data_len, len);

	if (offset != fsp->xfer_len) {
		/*
		 * this is we have handle some day
		 */
		eprintf("xfer-ready non-contiguous.  len %zx offset %zx\n",
			len, offset);
	} else {
		sp = fc_seq_start_next(sp);
		mfs = fc_seq_mfs(sp);
		remaining = len;
		tlen = 0;
		buf_offset = offset;

		while (remaining > 0) {

			if (!fp) {
				tlen = min(mfs, remaining);
				fp = fc_frame_alloc(fsp->openfcp->fcs_port, tlen);
				data = (void *) (fp->fr_hdr + 1);

				fc_frame_setup(fp, FC_RCTL_DD_SOL_DATA,
					       FC_TYPE_FCP);
				fc_frame_set_offset(fp, buf_offset);
			}

			dprintf("%zu %zu %zu\n", tlen, remaining, buf_offset);
			page_addr = (char *)scsi_get_in_buffer(&fsp->scmd) + buf_offset;

			memcpy(data, (char *) page_addr, tlen);

			data += tlen;

			buf_offset += tlen;
			remaining -= tlen;
			tlen = 0;
			if (remaining == 0) {
				error = fc_seq_send(sp, fp);
			} else if (tlen == 0) {
				error = fc_seq_send_frag(sp, fp);
			} else {
				continue;
			}

			dprintf("%zu %zu %d\n", tlen, remaining, error);
			fp = NULL;
			if (error) {
				/*
				 * we need to handle this case -XXX
				 */
				fc_seq_exch_complete(sp);
				break;
			}

		}

		fsp->xfer_len += len;	/* premature count? */
	}
}

int openfct_scsi_send_data_status(struct fc_scsi_pkt *pkt)
{
	if (scsi_get_data_dir(&pkt->scmd) == DATA_READ)
		openfc_scsi_send_data(pkt, pkt->seq_ptr);

	openfct_scsi_send_status(pkt);
	return 0;
}
