/*
 * Copyright(c) 2007 Intel Corporation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef _OPENFC_SCSI_TARGET_PKT_H_
#define _OPENFC_SCSI_TARGET_PKT_H_

#include "fc_fcp.h"
#include "fc_frame.h"
#include "fc_exch.h"


struct openfchba_softc;
#define DCEHBA_SRB_READ		   (1 << 1)
#define DCEHBA_SRB_WRITE	   (1 << 0)
/*
 * SRB state  definitions
 */
#define OPENFC_SRB_REC		   12	/* this is an internal REC pkt */
#define OPENFC_SRB_RESET	   11	/* for rest srb	 needs to free */
#define OPENFC_SRB_TIMEOUT	   10	/* cmd timed out */
#define OPENFC_SRB_TM_DONE	   9	/* cmd on watchdog list */
#define OPENFC_SRB_ABORTED	   8	/* cmd aborted command already */
#define OPENFC_SRB_ABORT_PENDING   7	/* cmd abort sent to device */
#define OPENFC_SRB_RCV_STATUS	   6	/* cmd has sense data */
#define OPENFC_SRB_WAIT_FOR_STATUS 5	/* waiting for status frame */
#define OPENFC_SRB_IN_DATA_TRANS   4	/* cmd in data transfer */
#define OPENFC_SRB_CMD_SENT	   3	/* cmd is sent */
#define OPENFC_SRB_CMD_BUILT	   2	/* cmd is built */
#define OPENFC_SRB_INIT		   1	/* INIT command. */
#define OPENFC_SRB_FREE		   0	/* cmd needs retrying */

#define OPENFC_SRB_READ		   (1 << 1)
#define OPENFC_SRB_WRITE	   (1 << 0)
/*
 * transport level status code
 */
#define DCEHBA_COMPLETE		    0
#define DCEHBA_CMD_ABORTED	    1
#define DCEHBA_CMD_RESET	    2
#define DCEHBA_CMD_PLOGO	    3
#define DCEHBA_SNS_RCV		    4
#define DCEHBA_TRANS_ERR	    5
#define DCEHBA_DATA_OVRRUN	    6
#define DCEHBA_DATA_UNDRUN	    7
#define DCEHBA_ERROR		    8

#define MAX_CMD_SIZE		    16

struct openfct_tgt;

#define TGT_DOWN 0
#define OPENFC_NEW_CMD 1
#define OPENFC_STATE_NEED_DATA 2
#define OPENFC_STATE_DATA_IN 3
#define OPENFC_CMD_DONE 4
#define OPENFC_CMD_STATE_DONE 4
#define OPENFC_CMD_WAIT_FOR_DATA 5

#define OPENFC_SENSE_VALID 1
/*
 * Status entry SCSI status bit definitions.
 */
#define SS_MASK				0xfff	/* Reserved bits BIT_12-BIT_15 */
#define SS_RESIDUAL_UNDER		1 << 11
#define SS_RESIDUAL_OVER		1 << 10
#define SS_SENSE_LEN_VALID		1 << 9
#define SS_RESPONSE_INFO_LEN_VALID	1 < 8

#define SS_RESERVE_CONFLICT		(1 << 4)|(1 << 3)
#define SS_BUSY_CONDITION		1 << 3
#define SS_CONDITION_MET		1 << 2
#define SS_CHECK_CONDITION		1 << 1


struct openfct_sess {
	struct list_head list;
	struct openfct_tgt *tgt;
	u_int32_t	fcid;
};

struct openfct_tgt {
	u_int32_t	handle;
	void	       *ha;
	int		datasegs_per_cmd, datasegs_per_cont;
	int		status;
	/* Target's flags, serialized by ha->hardware_lock */
	unsigned int	tgt_shutdown:1; /* The driver is being released */
	int	sess_count;	/* count sessions refing q2t_tgt */
	struct list_head sess_list;
};

static inline struct openfct_sess *openfct_find_sess_by_fcid(struct openfct_tgt
							     *tgt,
							     u_int32_t fcid)
{
	struct openfct_sess *sess, *sess_tmp;
	list_for_each_entry_safe(sess, sess_tmp, &tgt->sess_list, list) {
		if (fcid == (sess->fcid))
			return (sess);
	}
	return (NULL);
}


struct fc_scsi_pkt {
	struct fc_scsi_pkt *next;
	struct fc_scsi_pkt *prev;
	struct openfchba_softc *openfcp;	/* handle to hba struct */
	u_int16_t	flags;		/* scsi_pkt state flags */
	u_int16_t	state;		/* scsi_pkt state flags */
	unsigned int	id;
	u_int64_t	lun;
	u_int8_t	lunp[8];
	void	       *private;	/* this pvt ptr */
	uint32_t	data_len;
	int	cnt;
	int	ref_cnt;
	uint32_t	idx;		/* host given value */
	struct openfct_tgt *tgt;
	uint16_t	req_cnt;
	uint16_t	seg_cnt;
	unsigned short	use_sg;
	struct scatterlist *sg;
	int		bufflen;
	void	       *buffer;
	uint16_t	rq_result;
	uint16_t	scsi_status;
	unsigned char  *sense_buffer;
	unsigned int	sense_buffer_len;
	int		residual;
	struct openfct_sess *sess;
	int		t_state;
	uint16_t	exid;
	uint32_t	fcid;
	u_int8_t	cdb[MAX_CMD_SIZE];
	void		(*done) (struct fc_scsi_pkt *);
	struct fcp_cmnd cdb_cmd;	/* this is only used in fcoe */
	size_t		xfer_len;	/* onlye used by fcoe */
	size_t		cmd_len;	/* onlye used by fcoe */
	u_int8_t	cdb_status;
	u_int8_t	status_code;
	struct fc_seq  *seq_ptr;
	struct fc_remote_port   *rp;
	struct scsi_cmd scmd;
};

struct fc_scsi_pkt_head {
	struct fc_scsi_pkt *next;
	struct fc_scsi_pkt *prev;
};
#endif /* _OPENFC_SCSI_PKT_H_ */
