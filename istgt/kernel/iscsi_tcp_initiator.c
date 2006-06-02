/*
 * iSCSI Initiator over TCP/IP Data-Path
 *
 * Copyright (C) 2004 Dmitry Yusupov
 * Copyright (C) 2004 Alex Aizman
 * Copyright (C) 2005 - 2006 Mike Christie
 * Copyright (C) 2006 Red Hat, Inc.  All rights reserved.
 * maintained by open-iscsi@googlegroups.com
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * See the file COPYING included with this distribution for more details.
 *
 * Credits:
 *	Christoph Hellwig
 *	FUJITA Tomonori
 *	Arne Redlich
 *	Zhenyu Wang
 */

#include <linux/types.h>
#include <linux/list.h>
#include <linux/inet.h>
#include <linux/blkdev.h>
#include <linux/crypto.h>
#include <linux/delay.h>
#include <linux/kfifo.h>
#include <linux/scatterlist.h>
#include <linux/mutex.h>
#include <net/tcp.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi.h>
#include "scsi_transport_iscsi.h"

#include "iscsi_tcp.h"

#define ISCSI_TCP_VERSION "1.0-595"

MODULE_AUTHOR("Dmitry Yusupov <dmitry_yus@yahoo.com>, "
	      "Alex Aizman <itn780@yahoo.com>");
MODULE_DESCRIPTION("iSCSI/TCP data-path");
MODULE_LICENSE("GPL");
MODULE_VERSION(ISCSI_TCP_VERSION);
/* #define DEBUG_TCP */
#define DEBUG_ASSERT

#ifdef DEBUG_TCP
#define debug_tcp(fmt...) printk(KERN_INFO "tcp: " fmt)
#else
#define debug_tcp(fmt...)
#endif

#ifndef DEBUG_ASSERT
#ifdef BUG_ON
#undef BUG_ON
#endif
#define BUG_ON(expr)
#endif

static unsigned int iscsi_max_lun = 512;
module_param_named(max_lun, iscsi_max_lun, uint, S_IRUGO);

/*
 * must be called with session lock
 */
static void
__iscsi_ctask_cleanup(struct iscsi_conn *conn, struct iscsi_cmd_task *ctask)
{
	struct iscsi_tcp_cmd_task *tcp_ctask = ctask->dd_data;
	struct scsi_cmnd *sc;

	sc = ctask->sc;
	if (unlikely(!sc))
		return;

	tcp_ctask->xmstate = XMSTATE_IDLE;
	tcp_ctask->r2t = NULL;
}

/**
 * iscsi_data_rsp - SCSI Data-In Response processing
 * @conn: iscsi connection
 * @ctask: scsi command task
 **/
static int
iscsi_data_rsp(struct iscsi_conn *conn, struct iscsi_cmd_task *ctask)
{
	int rc;
	struct iscsi_tcp_conn *tcp_conn = conn->dd_data;
	struct iscsi_tcp_cmd_task *tcp_ctask = ctask->dd_data;
	struct iscsi_data_rsp *rhdr = (struct iscsi_data_rsp *)tcp_conn->in.hdr;
	struct iscsi_session *session = conn->session;
	int datasn = be32_to_cpu(rhdr->datasn);

	rc = iscsi_check_assign_cmdsn(session, (struct iscsi_nopin*)rhdr);
	if (rc)
		return rc;
	/*
	 * setup Data-In byte counter (gets decremented..)
	 */
	ctask->data_count = tcp_conn->in.datalen;

	if (tcp_conn->in.datalen == 0)
		return 0;

	if (ctask->datasn != datasn)
		return ISCSI_ERR_DATASN;

	ctask->datasn++;

	tcp_ctask->data_offset = be32_to_cpu(rhdr->offset);
	if (tcp_ctask->data_offset + tcp_conn->in.datalen > ctask->total_length)
		return ISCSI_ERR_DATA_OFFSET;

	if (rhdr->flags & ISCSI_FLAG_DATA_STATUS) {
		struct scsi_cmnd *sc = ctask->sc;

		conn->exp_statsn = be32_to_cpu(rhdr->statsn) + 1;
		if (rhdr->flags & ISCSI_FLAG_DATA_UNDERFLOW) {
			int res_count = be32_to_cpu(rhdr->residual_count);

			if (res_count > 0 &&
			    res_count <= sc->request_bufflen) {
				sc->resid = res_count;
				sc->result = (DID_OK << 16) | rhdr->cmd_status;
			} else
				sc->result = (DID_BAD_TARGET << 16) |
					rhdr->cmd_status;
		} else if (rhdr->flags & ISCSI_FLAG_DATA_OVERFLOW) {
			sc->resid = be32_to_cpu(rhdr->residual_count);
			sc->result = (DID_OK << 16) | rhdr->cmd_status;
		} else
			sc->result = (DID_OK << 16) | rhdr->cmd_status;
	}

	conn->datain_pdus_cnt++;
	return 0;
}

/**
 * iscsi_solicit_data_init - initialize first Data-Out
 * @conn: iscsi connection
 * @ctask: scsi command task
 * @r2t: R2T info
 *
 * Notes:
 *	Initialize first Data-Out within this R2T sequence and finds
 *	proper data_offset within this SCSI command.
 *
 *	This function is called with connection lock taken.
 **/
static void
iscsi_solicit_data_init(struct iscsi_conn *conn, struct iscsi_cmd_task *ctask,
			struct iscsi_r2t_info *r2t)
{
	struct iscsi_data *hdr;
	struct scsi_cmnd *sc = ctask->sc;
	struct iscsi_tcp_cmd_task *tcp_ctask = ctask->dd_data;

	hdr = &r2t->dtask.hdr;
	memset(hdr, 0, sizeof(struct iscsi_data));
	hdr->ttt = r2t->ttt;
	hdr->datasn = cpu_to_be32(r2t->solicit_datasn);
	r2t->solicit_datasn++;
	hdr->opcode = ISCSI_OP_SCSI_DATA_OUT;
	memcpy(hdr->lun, ctask->hdr->lun, sizeof(hdr->lun));
	hdr->itt = ctask->hdr->itt;
	hdr->exp_statsn = r2t->exp_statsn;
	hdr->offset = cpu_to_be32(r2t->data_offset);
	if (r2t->data_length > conn->max_xmit_dlength) {
		hton24(hdr->dlength, conn->max_xmit_dlength);
		r2t->data_count = conn->max_xmit_dlength;
		hdr->flags = 0;
	} else {
		hton24(hdr->dlength, r2t->data_length);
		r2t->data_count = r2t->data_length;
		hdr->flags = ISCSI_FLAG_CMD_FINAL;
	}
	conn->dataout_pdus_cnt++;

	r2t->sent = 0;

	iscsi_buf_init_iov(&r2t->headbuf, (char*)hdr,
			   sizeof(struct iscsi_hdr));

	if (sc->use_sg) {
		int i, sg_count = 0;
		struct scatterlist *sg = sc->request_buffer;

		r2t->sg = NULL;
		for (i = 0; i < sc->use_sg; i++, sg += 1) {
			/* FIXME: prefetch ? */
			if (sg_count + sg->length > r2t->data_offset) {
				int page_offset;

				/* sg page found! */

				/* offset within this page */
				page_offset = r2t->data_offset - sg_count;

				/* fill in this buffer */
				iscsi_buf_init_sg(&r2t->sendbuf, sg);
				r2t->sendbuf.sg.offset += page_offset;
				r2t->sendbuf.sg.length -= page_offset;

				/* xmit logic will continue with next one */
				r2t->sg = sg + 1;
				break;
			}
			sg_count += sg->length;
		}
		BUG_ON(r2t->sg == NULL);
	} else
		iscsi_buf_init_iov(&tcp_ctask->sendbuf,
			    (char*)sc->request_buffer + r2t->data_offset,
			    r2t->data_count);
}

/**
 * iscsi_r2t_rsp - iSCSI R2T Response processing
 * @conn: iscsi connection
 * @ctask: scsi command task
 **/
static int
iscsi_r2t_rsp(struct iscsi_conn *conn, struct iscsi_cmd_task *ctask)
{
	struct iscsi_r2t_info *r2t;
	struct iscsi_session *session = conn->session;
	struct iscsi_tcp_cmd_task *tcp_ctask = ctask->dd_data;
	struct iscsi_tcp_conn *tcp_conn = conn->dd_data;
	struct iscsi_r2t_rsp *rhdr = (struct iscsi_r2t_rsp *)tcp_conn->in.hdr;
	int r2tsn = be32_to_cpu(rhdr->r2tsn);
	int rc;

	if (tcp_conn->in.datalen)
		return ISCSI_ERR_DATALEN;

	if (tcp_ctask->exp_r2tsn && tcp_ctask->exp_r2tsn != r2tsn)
		return ISCSI_ERR_R2TSN;

	rc = iscsi_check_assign_cmdsn(session, (struct iscsi_nopin*)rhdr);
	if (rc)
		return rc;

	/* FIXME: use R2TSN to detect missing R2T */

	/* fill-in new R2T associated with the task */
	spin_lock(&session->lock);
	if (!ctask->sc || ctask->mtask ||
	     session->state != ISCSI_STATE_LOGGED_IN) {
		printk(KERN_INFO "iscsi_tcp: dropping R2T itt %d in "
		       "recovery...\n", ctask->itt);
		spin_unlock(&session->lock);
		return 0;
	}
	rc = __kfifo_get(tcp_ctask->r2tpool.queue, (void*)&r2t, sizeof(void*));
	BUG_ON(!rc);

	r2t->exp_statsn = rhdr->statsn;
	r2t->data_length = be32_to_cpu(rhdr->data_length);
	if (r2t->data_length == 0 ||
	    r2t->data_length > session->max_burst) {
		spin_unlock(&session->lock);
		return ISCSI_ERR_DATALEN;
	}

	r2t->data_offset = be32_to_cpu(rhdr->data_offset);
	if (r2t->data_offset + r2t->data_length > ctask->total_length) {
		spin_unlock(&session->lock);
		return ISCSI_ERR_DATALEN;
	}

	r2t->ttt = rhdr->ttt; /* no flip */
	r2t->solicit_datasn = 0;

	iscsi_solicit_data_init(conn, ctask, r2t);

	tcp_ctask->exp_r2tsn = r2tsn + 1;
	tcp_ctask->xmstate |= XMSTATE_SOL_HDR;
	__kfifo_put(tcp_ctask->r2tqueue, (void*)&r2t, sizeof(void*));
	__kfifo_put(conn->xmitqueue, (void*)&ctask, sizeof(void*));

	scsi_queue_work(session->host, &conn->xmitwork);
	conn->r2t_pdus_cnt++;
	spin_unlock(&session->lock);

	return 0;
}

static int iscsi_tcp_initiator_hdr_recv(struct iscsi_conn *conn)
{
	struct iscsi_session *session = conn->session;
	struct iscsi_tcp_conn *tcp_conn = conn->dd_data;
	struct iscsi_hdr *hdr = tcp_conn->in.hdr;
	int rc, opcode, ahslen = hdr->hlength << 2;
	uint32_t itt;

	rc = iscsi_tcp_hdr_recv(conn);
	if (rc)
		return rc;

	opcode = hdr->opcode & ISCSI_OPCODE_MASK;
	/* verify itt (itt encoding: age+cid+itt) */
	rc = iscsi_verify_itt(conn, hdr, &itt);
	if (rc == ISCSI_ERR_NO_SCSI_CMD) {
		tcp_conn->in.datalen = 0; /* force drop */
		return 0;
	} else if (rc)
		return rc;

	debug_tcp("opcode 0x%x offset %d copy %d ahslen %d datalen %d\n",
		  opcode, tcp_conn->in.offset, tcp_conn->in.copy,
		  ahslen, tcp_conn->in.datalen);

	switch(opcode) {
	case ISCSI_OP_SCSI_DATA_IN:
		tcp_conn->in.ctask = session->cmds[itt];
		rc = iscsi_data_rsp(conn, tcp_conn->in.ctask);
		/* fall through */
	case ISCSI_OP_SCSI_CMD_RSP:
		tcp_conn->in.ctask = session->cmds[itt];
		if (tcp_conn->in.datalen)
			goto copy_hdr;

		spin_lock(&session->lock);
		__iscsi_ctask_cleanup(conn, tcp_conn->in.ctask);
		rc = __iscsi_complete_pdu(conn, hdr, NULL, 0);
		spin_unlock(&session->lock);
		break;
	case ISCSI_OP_R2T:
		tcp_conn->in.ctask = session->cmds[itt];
		if (ahslen)
			rc = ISCSI_ERR_AHSLEN;
		else if (tcp_conn->in.ctask->sc->sc_data_direction ==
								DMA_TO_DEVICE)
			rc = iscsi_r2t_rsp(conn, tcp_conn->in.ctask);
		else
			rc = ISCSI_ERR_PROTO;
		break;
	case ISCSI_OP_LOGIN_RSP:
	case ISCSI_OP_TEXT_RSP:
	case ISCSI_OP_LOGOUT_RSP:
	case ISCSI_OP_NOOP_IN:
	case ISCSI_OP_REJECT:
	case ISCSI_OP_ASYNC_EVENT:
		if (tcp_conn->in.datalen)
			goto copy_hdr;
	/* fall through */
	case ISCSI_OP_SCSI_TMFUNC_RSP:
		rc = iscsi_complete_pdu(conn, hdr, NULL, 0);
		break;
	default:
		rc = ISCSI_ERR_BAD_OPCODE;
		break;
	}

	return rc;

copy_hdr:
	/*
	 * if we did zero copy for the header but we will need multiple
	 * skbs to complete the command then we have to copy the header
	 * for later use
	 */
	if (tcp_conn->in.zero_copy_hdr && tcp_conn->in.copy <
	   (tcp_conn->in.datalen + tcp_conn->in.padding +
	    (conn->datadgst_en ? 4 : 0))) {
		debug_tcp("Copying header for later use. in.copy %d in.datalen"
			  " %d\n", tcp_conn->in.copy, tcp_conn->in.datalen);
		memcpy(&tcp_conn->hdr, tcp_conn->in.hdr,
		       sizeof(struct iscsi_hdr));
		tcp_conn->in.hdr = &tcp_conn->hdr;
		tcp_conn->in.zero_copy_hdr = 0;
	}
	return 0;
}

static void iscsi_scsi_data_in_done(struct iscsi_conn *conn)
{
	struct iscsi_tcp_conn *tcp_conn = conn->dd_data;
	struct iscsi_cmd_task *ctask = tcp_conn->in.ctask;

	if (tcp_conn->in.hdr->flags & ISCSI_FLAG_DATA_STATUS) {
		debug_scsi("done [sc %p res %d itt 0x%x]\n", ctask->sc,
			   (struct scsi_cmnd *) (ctask->sc)->result, ctask->itt);
		spin_lock(&conn->session->lock);
		__iscsi_ctask_cleanup(conn, ctask);
		__iscsi_complete_pdu(conn, tcp_conn->in.hdr, NULL, 0);
		spin_unlock(&conn->session->lock);
	}
}

static int
iscsi_tcp_initiator_data_recv(struct iscsi_conn *conn)
{
	struct iscsi_tcp_conn *tcp_conn = conn->dd_data;
	int rc = 0, opcode;

	opcode = tcp_conn->in.hdr->opcode & ISCSI_OPCODE_MASK;
	switch (opcode) {
	case ISCSI_OP_SCSI_DATA_IN:
		rc = iscsi_scsi_data_in(conn);
		if (!rc)
			iscsi_scsi_data_in_done(conn);
		break;
	case ISCSI_OP_SCSI_CMD_RSP:
		spin_lock(&conn->session->lock);
		__iscsi_ctask_cleanup(conn, tcp_conn->in.ctask);
		spin_unlock(&conn->session->lock);
	case ISCSI_OP_TEXT_RSP:
	case ISCSI_OP_LOGIN_RSP:
	case ISCSI_OP_NOOP_IN:
	case ISCSI_OP_ASYNC_EVENT:
	case ISCSI_OP_REJECT:
		/*
		 * Collect data segment to the connection's data
		 * placeholder
		 */
		if (iscsi_tcp_copy(tcp_conn)) {
			rc = -EAGAIN;
			goto exit;
		}

		rc = iscsi_complete_pdu(conn, tcp_conn->in.hdr, tcp_conn->data,
					tcp_conn->in.datalen);
		if (!rc && conn->datadgst_en && opcode != ISCSI_OP_LOGIN_RSP)
			iscsi_recv_digest_update(tcp_conn, tcp_conn->data,
			  			tcp_conn->in.datalen);
		break;
	default:
		BUG_ON(1);
	}
exit:
	return rc;
}

static void
iscsi_unsolicit_data_init(struct iscsi_conn *conn, struct iscsi_cmd_task *ctask)
{
	struct iscsi_tcp_cmd_task *tcp_ctask = ctask->dd_data;
	struct iscsi_data_task *dtask;

	dtask = tcp_ctask->dtask = &tcp_ctask->unsol_dtask;
	iscsi_prep_unsolicit_data_pdu(ctask, &dtask->hdr,
				      tcp_ctask->r2t_data_count);
	iscsi_buf_init_iov(&tcp_ctask->headbuf, (char*)&dtask->hdr,
			   sizeof(struct iscsi_hdr));
}

/**
 * iscsi_tcp_cmd_init - Initialize iSCSI SCSI_READ or SCSI_WRITE commands
 * @conn: iscsi connection
 * @ctask: scsi command task
 * @sc: scsi command
 **/
static void
iscsi_tcp_cmd_init(struct iscsi_cmd_task *ctask)
{
	struct scsi_cmnd *sc = ctask->sc;
	struct iscsi_tcp_cmd_task *tcp_ctask = ctask->dd_data;

	BUG_ON(__kfifo_len(tcp_ctask->r2tqueue));

	tcp_ctask->sent = 0;
	tcp_ctask->sg_count = 0;

	if (sc->sc_data_direction == DMA_TO_DEVICE) {
		tcp_ctask->xmstate = XMSTATE_W_HDR;
		tcp_ctask->exp_r2tsn = 0;
		BUG_ON(ctask->total_length == 0);

		if (sc->use_sg) {
			struct scatterlist *sg = sc->request_buffer;

			iscsi_buf_init_sg(&tcp_ctask->sendbuf,
					  &sg[tcp_ctask->sg_count++]);
			tcp_ctask->sg = sg;
			tcp_ctask->bad_sg = sg + sc->use_sg;
		} else
			iscsi_buf_init_iov(&tcp_ctask->sendbuf,
					   sc->request_buffer,
					   sc->request_bufflen);

		if (ctask->imm_count)
			tcp_ctask->xmstate |= XMSTATE_IMM_DATA;

		tcp_ctask->pad_count = ctask->total_length & (ISCSI_PAD_LEN-1);
		if (tcp_ctask->pad_count) {
			tcp_ctask->pad_count = ISCSI_PAD_LEN -
							tcp_ctask->pad_count;
			debug_scsi("write padding %d bytes\n",
				   tcp_ctask->pad_count);
			tcp_ctask->xmstate |= XMSTATE_W_PAD;
		}

		if (ctask->unsol_count)
			tcp_ctask->xmstate |= XMSTATE_UNS_HDR |
						XMSTATE_UNS_INIT;
		tcp_ctask->r2t_data_count = ctask->total_length -
				    ctask->imm_count -
				    ctask->unsol_count;

		debug_scsi("cmd [itt %x total %d imm %d imm_data %d "
			   "r2t_data %d]\n",
			   ctask->itt, ctask->total_length, ctask->imm_count,
			   ctask->unsol_count, tcp_ctask->r2t_data_count);
	} else
		tcp_ctask->xmstate = XMSTATE_R_HDR;

	iscsi_buf_init_iov(&tcp_ctask->headbuf, (char*)ctask->hdr,
			    sizeof(struct iscsi_hdr));
}

static struct iscsi_tcp_operations iscsi_tcp_initiator_ops = {
	.hdr_recv		=	iscsi_tcp_initiator_hdr_recv,
	.data_recv		=	iscsi_tcp_initiator_data_recv,
	.unsolicit_data_init	=	iscsi_unsolicit_data_init,
};

static struct iscsi_cls_conn *
iscsi_tcp_initiator_conn_create(struct iscsi_cls_session *cls_session,
				uint32_t conn_idx)
{
	return iscsi_tcp_conn_create(cls_session, conn_idx,
				     &iscsi_tcp_initiator_ops);
}

static void
iscsi_tcp_cleanup_ctask(struct iscsi_conn *conn, struct iscsi_cmd_task *ctask)
{
	struct iscsi_tcp_cmd_task *tcp_ctask = ctask->dd_data;
	struct iscsi_r2t_info *r2t;

	/* flush ctask's r2t queues */
	while (__kfifo_get(tcp_ctask->r2tqueue, (void*)&r2t, sizeof(void*)))
		__kfifo_put(tcp_ctask->r2tpool.queue, (void*)&r2t,
			    sizeof(void*));

	__iscsi_ctask_cleanup(conn, ctask);
}

static void
iscsi_tcp_suspend_conn_rx(struct iscsi_conn *conn)
{
	struct iscsi_tcp_conn *tcp_conn = conn->dd_data;
	struct sock *sk;

	if (!tcp_conn->sock)
		return;

	sk = tcp_conn->sock->sk;
	write_lock_bh(&sk->sk_callback_lock);
	set_bit(ISCSI_SUSPEND_BIT, &conn->suspend_rx);
	write_unlock_bh(&sk->sk_callback_lock);
}

/* called with host lock */
static void
iscsi_tcp_mgmt_init(struct iscsi_conn *conn, struct iscsi_mgmt_task *mtask,
		    char *data, uint32_t data_size)
{
	struct iscsi_tcp_mgmt_task *tcp_mtask = mtask->dd_data;

	iscsi_buf_init_iov(&tcp_mtask->headbuf, (char*)mtask->hdr,
			   sizeof(struct iscsi_hdr));
	tcp_mtask->xmstate = XMSTATE_IMM_HDR;

	if (mtask->data_count)
		iscsi_buf_init_iov(&tcp_mtask->sendbuf, (char*)mtask->data,
				    mtask->data_count);
}

/**
 * iscsi_tcp_mtask_xmit - xmit management(immediate) task
 * @conn: iscsi connection
 * @mtask: task management task
 *
 * Notes:
 *	The function can return -EAGAIN in which case caller must
 *	call it again later, or recover. '0' return code means successful
 *	xmit.
 *
 *	Management xmit state machine consists of two states:
 *		IN_PROGRESS_IMM_HEAD - PDU Header xmit in progress
 *		IN_PROGRESS_IMM_DATA - PDU Data xmit in progress
 **/
static int
iscsi_tcp_mtask_xmit(struct iscsi_conn *conn, struct iscsi_mgmt_task *mtask)
{
	struct iscsi_tcp_mgmt_task *tcp_mtask = mtask->dd_data;
	int rc;

	debug_scsi("mtask deq [cid %d state %x itt 0x%x]\n",
		conn->id, tcp_mtask->xmstate, mtask->itt);

	if (tcp_mtask->xmstate & XMSTATE_IMM_HDR) {
		tcp_mtask->xmstate &= ~XMSTATE_IMM_HDR;
		if (mtask->data_count)
			tcp_mtask->xmstate |= XMSTATE_IMM_DATA;
		if (conn->c_stage != ISCSI_CONN_INITIAL_STAGE &&
		    conn->stop_stage != STOP_CONN_RECOVER &&
		    conn->hdrdgst_en)
			iscsi_hdr_digest(conn, &tcp_mtask->headbuf,
					(u8*)tcp_mtask->hdrext);
		rc = iscsi_sendhdr(conn, &tcp_mtask->headbuf,
				   mtask->data_count);
		if (rc) {
			tcp_mtask->xmstate |= XMSTATE_IMM_HDR;
			if (mtask->data_count)
				tcp_mtask->xmstate &= ~XMSTATE_IMM_DATA;
			return rc;
		}
	}

	if (tcp_mtask->xmstate & XMSTATE_IMM_DATA) {
		BUG_ON(!mtask->data_count);
		tcp_mtask->xmstate &= ~XMSTATE_IMM_DATA;
		/* FIXME: implement.
		 * Virtual buffer could be spreaded across multiple pages...
		 */
		do {
			int rc;

			rc = iscsi_sendpage(conn, &tcp_mtask->sendbuf,
					&mtask->data_count, &tcp_mtask->sent);
			if (rc) {
				tcp_mtask->xmstate |= XMSTATE_IMM_DATA;
				return rc;
			}
		} while (mtask->data_count);
	}

	BUG_ON(tcp_mtask->xmstate != XMSTATE_IDLE);
	if (mtask->hdr->itt == cpu_to_be32(ISCSI_RESERVED_TAG)) {
		struct iscsi_session *session = conn->session;

		spin_lock_bh(&session->lock);
		list_del(&conn->mtask->running);
		__kfifo_put(session->mgmtpool.queue, (void*)&conn->mtask,
			    sizeof(void*));
		spin_unlock_bh(&session->lock);
	}
	return 0;
}

static struct scsi_host_template iscsi_sht = {
	.name			= "iSCSI Initiator over TCP/IP, v"
				  ISCSI_TCP_VERSION,
	.queuecommand           = iscsi_queuecommand,
	.change_queue_depth	= iscsi_change_queue_depth,
	.can_queue		= ISCSI_XMIT_CMDS_MAX - 1,
	.sg_tablesize		= ISCSI_SG_TABLESIZE,
	.cmd_per_lun		= ISCSI_DEF_CMD_PER_LUN,
	.eh_abort_handler       = iscsi_eh_abort,
	.eh_host_reset_handler	= iscsi_eh_host_reset,
	.use_clustering         = DISABLE_CLUSTERING,
	.proc_name		= "iscsi_tcp",
	.this_id		= -1,
};

static struct iscsi_transport iscsi_tcp_transport = {
	.owner			= THIS_MODULE,
	.name			= "tcp",
	.caps			= CAP_RECOVERY_L0 | CAP_MULTI_R2T | CAP_HDRDGST
				  | CAP_DATADGST,
	.param_mask		= ISCSI_MAX_RECV_DLENGTH |
				  ISCSI_MAX_XMIT_DLENGTH |
				  ISCSI_HDRDGST_EN |
				  ISCSI_DATADGST_EN |
				  ISCSI_INITIAL_R2T_EN |
				  ISCSI_MAX_R2T |
				  ISCSI_IMM_DATA_EN |
				  ISCSI_FIRST_BURST |
				  ISCSI_MAX_BURST |
				  ISCSI_PDU_INORDER_EN |
				  ISCSI_DATASEQ_INORDER_EN |
				  ISCSI_ERL |
				  ISCSI_CONN_PORT |
				  ISCSI_CONN_ADDRESS |
				  ISCSI_EXP_STATSN,
	.host_template		= &iscsi_sht,
	.conndata_size		= sizeof(struct iscsi_conn),
	.max_conn		= 1,
	.max_cmd_len		= ISCSI_TCP_MAX_CMD_LEN,
	/* session management */
	.create_session		= iscsi_tcp_session_create,
	.destroy_session	= iscsi_tcp_session_destroy,
	/* connection management */
	.create_conn		= iscsi_tcp_initiator_conn_create,
	.bind_conn		= iscsi_tcp_conn_bind,
	.destroy_conn		= iscsi_tcp_conn_destroy,
	.set_param		= iscsi_conn_set_param,
	.get_conn_param		= iscsi_conn_get_param,
	.get_conn_str_param	= iscsi_conn_get_str_param,
	.get_session_param	= iscsi_session_get_param,
	.start_conn		= iscsi_conn_start,
	.stop_conn		= iscsi_conn_stop,
	/* these are called as part of conn recovery */
	.suspend_conn_recv	= iscsi_tcp_suspend_conn_rx,
	.terminate_conn		= iscsi_tcp_terminate_conn,
	/* IO */
	.send_pdu		= iscsi_conn_send_pdu,
	.get_stats		= iscsi_conn_get_stats,
	.init_cmd_task		= iscsi_tcp_cmd_init,
	.init_mgmt_task		= iscsi_tcp_mgmt_init,
	.xmit_cmd_task		= iscsi_tcp_ctask_xmit,
	.xmit_mgmt_task		= iscsi_tcp_mtask_xmit,
	.cleanup_cmd_task	= iscsi_tcp_cleanup_ctask,
	/* recovery */
	.session_recovery_timedout = iscsi_session_recovery_timedout,
};

static int __init
iscsi_tcp_init(void)
{
	if (iscsi_max_lun < 1) {
		printk(KERN_ERR "iscsi_tcp: Invalid max_lun value of %u\n",
		       iscsi_max_lun);
		return -EINVAL;
	}
	iscsi_tcp_transport.max_lun = iscsi_max_lun;

	if (!iscsi_register_transport(&iscsi_tcp_transport))
		return -ENODEV;

	return 0;
}

static void __exit
iscsi_tcp_exit(void)
{
	iscsi_unregister_transport(&iscsi_tcp_transport);
}

module_init(iscsi_tcp_init);
module_exit(iscsi_tcp_exit);
