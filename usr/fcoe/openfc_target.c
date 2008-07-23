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
#include "scsi.h"
#include "target.h"

#include "fc_types.h"
#include "fc_port.h"
#include "fc_frame.h"
#include "fc_event.h"
#include "fc_remote_port.h"
#include "fcdev.h"
#include "openfc_target.h"
#include "openfc_scst_pkt.h"
#include "fcs_state.h"
#include "fc_fcp.h"
#include "fc_encaps.h"

extern void openfct_rcv_cmd(struct fc_seq *sp, struct fc_frame *fp, void *arg);
extern void openfct_send_xfer_rdy(struct fc_scsi_pkt *);
extern void openfct_scsi_send_status(struct fc_scsi_pkt *pkt);
extern int openfct_scsi_send_data_status(struct fc_scsi_pkt *pkt);
extern void openfct_scsi_send_tmf_rsp(struct fc_scsi_pkt *pkt, uint8_t rsp);

static struct target *fc_target;

static struct openfct_sess *openfct_find_sess_by_fcid(struct openfct_tgt *tgt,
						      u_int32_t fcid)
{
	struct openfct_sess *sess;
	list_for_each_entry(sess, &tgt->sess_list, list) {
		if (fcid == sess->fcid)
			return sess;
	}
	return NULL;
}

int fcoe_cmd_done(uint64_t nid, int result, struct scsi_cmd *scmd)
{
	struct fc_scsi_pkt *pkt = container_of(scmd, struct fc_scsi_pkt, scmd);
	int data_sense_flag = 0;

	dprintf("%p %d\n", scmd, scsi_get_result(scmd));

	pkt->rq_result = scsi_get_result(scmd);
	pkt->sense_buffer = scmd->sense_buffer;
	pkt->sense_buffer_len = scmd->sense_len;

	if (scsi_get_data_dir(scmd) == DATA_WRITE) {
		pkt->bufflen = scsi_get_out_length(scmd) - scsi_get_out_resid(scmd);
		openfct_scsi_send_status(pkt);
	} else {
		pkt->bufflen = scsi_get_in_length(scmd) - scsi_get_in_resid(scmd);
		pkt->residual = scsi_get_in_resid(scmd);

		if (scsi_get_result(scmd) != SAM_STAT_GOOD) {
			pkt->flags |= OPENFC_SENSE_VALID;
			pkt->rq_result |= SS_SENSE_LEN_VALID;
			data_sense_flag = 1;
		}
		if (pkt->residual > 0) {
			pkt->rq_result |= SS_RESIDUAL_UNDER;
		} else if (pkt->residual < 0) {
/* 			pkt->rq_result |= SS_RESIDUAL_OVER; */
		}
		if (pkt->bufflen > 0)
			openfct_scsi_send_data_status(pkt);
		else
			openfct_scsi_send_status(pkt);
	}

	return 0;
}

static int cmd_attr(struct fcp_cmnd *fcmd)
{
	int attr;

	switch (fcmd->fc_pri_ta) {
	case FCP_PTA_SIMPLE:
		attr = MSG_SIMPLE_TAG;
		break;
	case FCP_PTA_HEADQ:
		attr = MSG_HEAD_TAG;
		break;
	case FCP_PTA_ORDERED:
	default:
		attr = MSG_ORDERED_TAG;
	}
	return attr;
}

int fcoe_tmf_done(struct mgmt_req *mreq)
{
	struct fc_scsi_pkt *pkt;
	uint8_t rsp;

	dprintf("tmf result %d\n", mreq->result);

	pkt = (struct fc_scsi_pkt *) (unsigned long) mreq->mid;
	switch (mreq->result) {
	case 0:
		rsp = FCP_TMF_CMPL;
		break;
	default:
		/* we do not seem to get enough info to return something else */
		rsp = FCP_TMF_FAILED;
	}

	openfct_scsi_send_tmf_rsp(pkt, rsp);
	return 0;
}

static int openfct_process_tmf(struct fc_scsi_pkt *fsp, struct fcp_cmnd *fcmd)
{
	int fn = 0, err = 0;

	dprintf("tmf cmd %0x\n", fcmd->fc_tm_flags);

	switch (fcmd->fc_tm_flags) {
	case FCP_TMF_LUN_RESET:
		fn = LOGICAL_UNIT_RESET;
		break;
	default:
		err = -ENOSYS;
		eprintf("Unsupported task management function %d.\n",
			fcmd->fc_tm_flags);
	}

	if (!err) {
		fsp->flags |= OPENFC_TMF_PKT;
		/* tid is busted - need a target create */
		target_mgmt_request(fc_target->tid, fsp->fcid,
				    (unsigned long ) fsp, fn,
				    fcmd->fc_lun, fsp->exid, 0);
	}
	return err;

}

int openfct_process_scsi_cmd(struct openfchba_softc *openfcp,
			     struct fc_scsi_pkt *fsp, struct fcp_cmnd *fcmd)
{
	struct scsi_cmd *scmd = &fsp->scmd;
	u_int32_t fcid;
	struct openfct_tgt *tgt;
	struct openfct_sess *sess;
	int rc = 0;
	char *buf;
	int do_queue = 1;

	tgt = openfcp->tgt;
	fcid = fsp->fcid;
	fsp->openfcp = openfcp;

	if (tgt->tgt_shutdown) {
		rc = -EFAULT;
		goto out;
	}
	fsp->t_state = OPENFC_NEW_CMD;
	sess = openfct_find_sess_by_fcid(tgt, fcid);

	if (!sess) {
		eprintf(" fid is %x not found \n", fcid);
		rc = -EFAULT;
		goto out;
	}

	fsp->tgt = tgt;

	if (fcmd->fc_tm_flags)
		return openfct_process_tmf(fsp, fcmd);

	memcpy(scmd->lun, fsp->lunp, 8);
	scmd->scb = fsp->cdb;
	scmd->tag = fsp->exid;
	scmd->cmd_itn_id = sess->fcid;
	scmd->scb_len = sizeof(fsp->cdb);
	scmd->attribute = cmd_attr(fcmd);

	buf = malloc(fsp->data_len);
	if (!buf)
		goto out;
	fsp->bufflen = fsp->data_len;

	if (fcmd->fc_flags & 0x2) {
		scsi_set_data_dir(scmd, DATA_READ);
		scsi_set_in_length(scmd, fsp->data_len);
		scsi_set_in_buffer(scmd, buf);
	} else if (fcmd->fc_flags & 0x1) {
		scsi_set_data_dir(scmd, DATA_WRITE);
		scsi_set_out_length(scmd, fsp->data_len);
		scsi_set_out_buffer(scmd, buf);
		do_queue = 0;
	} else
		scsi_set_data_dir(scmd, DATA_NONE);

	dprintf("%p %d %x %d\n", scmd, do_queue, fcmd->fc_flags, fsp->data_len);

	if (do_queue)
		target_cmd_queue(1, scmd);
	else {
		fsp->t_state = OPENFC_CMD_WAIT_FOR_DATA;
		openfct_send_xfer_rdy(fsp);
	}
out:
	/* free the scsi pkt */
	return rc;
}

static int openfct_session_create(void *arg, struct fc_remote_port *port)
{
	struct openfchba_softc *openfcp = (struct openfchba_softc *) arg;
	struct openfct_tgt *tgt;
	struct openfct_sess *sess;
	int		rc = 0;

	tgt = openfcp->tgt;
	dprintf("%p %p\n", openfcp, tgt);

	sess = openfct_find_sess_by_fcid(tgt, port->rp_fid);
	if (!sess) {
		sess = zalloc(sizeof(*sess));
		if (!sess) {
			rc = -1;
			goto out;
		}
		sess->tgt = tgt;
		sess->fcid = port->rp_fid;
		INIT_LIST_HEAD(&sess->list);

		it_nexus_create(1, port->rp_fid, 0, (void *)sess);
		list_add(&sess->list, &tgt->sess_list);
		tgt->sess_count++;
	}
out:
	return rc;
}

static void openfct_discovery_done(void *arg)
{
	struct openfchba_softc *openfcp = (struct openfchba_softc *) arg;
	struct openfct_tgt *tgt;

	dprintf("%p %d\n", openfcp, openfcp->state);

	if (openfcp->state != OPENFC_FCS_INITIALIZATION) {
		/*
		 * this is the case for link down and link up
		 * in this case we do not need to do scsi_scan_bus again
		 */
		return;
	}
	openfcp->state = OPENFC_RUNNING;

	tgt = zalloc(sizeof(*tgt));
	if (!tgt) {
		openfcp->state = 0;
		return;
	}

	dprintf("%p\n", tgt);

	tgt->ha = openfcp;
	openfcp->tgt = tgt;
	tgt->status = TGT_DOWN;
	tgt->tgt_shutdown = 0;
	INIT_LIST_HEAD(&tgt->sess_list);
	tgt->sess_count = 0;
}

static inline struct openfchba_softc *openfc_get_softc(struct fcdev *dev)
{
	return container_of(dev, struct openfchba_softc, fd);
}

void openfc_rcv(struct fcdev *dev, struct fc_frame *fp)
{
	struct openfchba_softc *openfcp = openfc_get_softc(dev);
	struct fc_port *portp = openfcp->fcs_port;
	fc_port_ingress(portp, fp);
}

struct fcdev *openfc_alloc_dev(struct openfc_port_operations *fctt,
			       int privsize)
{
	struct fcdev *fc_dev;
	struct openfchba_softc *openfcp;

	openfcp = zalloc(sizeof(struct openfchba_softc) + privsize
			 + sizeof(struct fcdev));
	openfcp->dev = &openfcp->fd;
	fc_dev = openfcp->dev;

	INIT_LIST_HEAD(&openfcp->rplist);
	/*
	 * FCS initialization starts here
	 * create fcs structures here
	 */
	openfcp->state = OPENFC_FCS_INITIALIZATION;
	openfcp->fcs_port = fc_port_alloc();

	if (fctt->send) {
		openfcp->dev->port_ops.send = fctt->send;
	} else {
		goto error;
	}
	if (fctt->frame_alloc) {
		openfcp->dev->port_ops.frame_alloc = fctt->frame_alloc;
	} else {
		goto error;
	}

	openfcp->dev->port_ops.frame_alloc = fctt->frame_alloc;
	fc_dev->drv_priv = (void *) (fc_dev + 1);


	return fc_dev;
error:
	free(openfcp);
	return NULL;

}

static void openfct_port_logout(void *arg, struct fc_remote_port *port)
{
	struct openfchba_softc *openfcp = (struct openfchba_softc *) arg;
	struct openfct_sess *sess;
	u_int32_t fcid = port->rp_fid;

	sess = openfct_find_sess_by_fcid(openfcp->tgt, fcid);
	if (sess) {
		list_del(&sess->list);
		it_nexus_destroy(1, fcid);
	}
}

static struct fcs_create_args openfct_fcs_args = {
	.fca_disc_done = openfct_discovery_done,
	.fca_fcp_recv = openfct_rcv_cmd,
	.fca_prli_accept = openfct_session_create,
	.fca_prlo_notify = openfct_port_logout,
	.fca_service_params = FCP_SPPF_TARG_FCN | FCP_SPPF_RD_XRDY_DIS,
	.fca_min_xid = 0x0004,	/* starting XID */
        .fca_max_xid = 0x07ef,  /* 2K with room for exch_mgr */
        .fca_e_d_tov = 2 * 1000,        /* FC-FS default */

};

/*
 * We currently only support one target
 */
int fcoe_target_create(struct target *t)
{
	if (fc_target) {
		eprintf("Only one fcoe target supported. Currently fcoe tid "
			"%u is running\n", fc_target->tid);
		return -EINVAL;
	}
	fc_target = t;
	return 0;
}

void fcoe_target_destroy(int tid)
{
	if (!fc_target)
		return;
	if (fc_target->tid != tid)
		return;
	fc_target = NULL;
}

/**
 * openfct_attach: Called by bus code for each adapter
 */
int openfc_register(struct fcdev *dev)
{
	struct openfchba_softc *openfcp;
	struct fc_port *port;

	openfcp = openfc_get_softc(dev);
	openfct_fcs_args.fca_port = openfcp->fcs_port;
	openfct_fcs_args.fca_cb_arg = (void *) openfcp;
	port = openfcp->fcs_port;
	/*
	 * if the mtu is larger then FC mtu then set it to FC_MTU
	 * otherwise use Ethernet MTU - 24
	 */
	dprintf(" mtu %d\n", dev->framesize);
	if (dev->port_ops.frame_alloc)
		fc_port_set_frame_alloc(port, dev->port_ops.frame_alloc);

	fc_port_set_egress(port,
			   (int (*)(void *, struct fc_frame *)) dev->port_ops.
			   send, dev);

	fc_port_set_max_frame_size(openfcp->fcs_port, dev->framesize);
	openfcp->fcs_state = fcs_create(&openfct_fcs_args);
	if (!openfcp->fcs_state) {
		eprintf("Could not create fcs_state structure\n");
		return -1;
	}

	openfcp->state = OPENFC_FCS_INITIALIZATION;
	openfcp->status = OPENFC_LINK_UP;

	fcs_local_port_set(openfcp->fcs_state, openfcp->dev->fd_wwnn,
			   openfcp->dev->fd_wwpn);
	fcs_start(openfcp->fcs_state);

	return 0;
}
