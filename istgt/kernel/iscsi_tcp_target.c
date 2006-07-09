/*
 * iSCSI Target over TCP/IP
 *
 * Copyright (C) 2006 FUJITA Tomonori <tomof@acm.org>
 * Copyright (C) 2006 Mike Christie <michaelc@cs.wisc.edu>
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
 */

#include <linux/list.h>
#include <linux/inet.h>
#include <linux/kfifo.h>
#include <net/tcp.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi.h>
#include <scsi/scsi_tgt.h>
#include <scsi/scsi_tcq.h>
#include "iscsi_tcp.h"
#include "libiscsi.h"
#include "scsi_transport_iscsi.h"
#include "iscsi_tcp.h"

/* tmp - will replace with SCSI logging stuff */
#define eprintk(fmt, args...)					\
do {								\
	printk("%s(%d) " fmt, __FUNCTION__, __LINE__, ##args);	\
} while (0)

#define dprintk eprintk

struct istgt_session {
	struct list_head cmd_pending;
	struct list_head cmd_hash;
};

static struct workqueue_struct *recvwq;

static void hashlist_add(struct iscsi_cls_session *cls_session,
			 struct iscsi_cmd_task *ctask)
{
	struct iscsi_session *session = class_to_transport_session(cls_session);
	struct istgt_session *istgt_session = cls_session->dd_data;

	spin_lock_bh(&session->lock);
	list_add(&ctask->hash, &istgt_session->cmd_hash);
	spin_unlock_bh(&session->lock);
}

static struct iscsi_cmd_task *hashlist_find(struct iscsi_cls_session *cls_session, u32 itt)
{
	struct iscsi_cmd_task *ctask = NULL;
	struct iscsi_session *session = class_to_transport_session(cls_session);
	struct istgt_session *istgt_session = cls_session->dd_data;

	spin_lock_bh(&session->lock);
	list_for_each_entry(ctask, &istgt_session->cmd_hash, hash) {
		if (ctask->hdr->itt == itt)
			goto found;
	}
	ctask = NULL;
found:
	spin_unlock_bh(&session->lock);
	return ctask;
}

static void iscsi_tcp_tgt_ctask_xmitqueue(struct iscsi_cmd_task *ctask)
{
	struct iscsi_conn *conn = ctask->conn;
	struct iscsi_cls_session *cls_session = session_to_cls(conn->session);
	struct Scsi_Host *shost = iscsi_session_to_shost(cls_session);

	spin_lock_bh(&conn->session->lock);
	__kfifo_put(conn->xmitqueue, (void*)&ctask, sizeof(void*));
	spin_unlock_bh(&conn->session->lock);
	scsi_queue_work(shost, &conn->xmitwork);
}

static void iscsi_tcp_tgt_ctask_cleanup(struct iscsi_cmd_task *ctask)
{
	struct iscsi_conn *conn = ctask->conn;

	dprintk("%p %p\n", ctask, conn->session);
	spin_lock_bh(&conn->session->lock);
	list_del(&ctask->hash);
	list_del_init(&ctask->running);
	__kfifo_put(conn->session->cmdpool.queue, (void*)&ctask, sizeof(void*));
	spin_unlock_bh(&conn->session->lock);
}

static void iscsi_tcp_tgt_sc_queue(struct iscsi_cmd_task *ctask)
{
	struct iscsi_session *session = ctask->conn->session;
	struct iscsi_cls_session *cls_session = session_to_cls(session);
	struct Scsi_Host *shost = iscsi_session_to_shost(cls_session);
	struct iscsi_cmd *hdr = ctask->hdr;
	struct scsi_cmnd *scmd;
	enum dma_data_direction dir = (hdr->flags & ISCSI_FLAG_CMD_WRITE) ?
		DMA_TO_DEVICE : DMA_FROM_DEVICE;

	scmd = scsi_host_get_command(shost, dir, GFP_ATOMIC);
	BUG_ON(!scmd);
	ctask->sc = scmd;
	memcpy(scmd->cmnd, hdr->cdb, MAX_COMMAND_SIZE);
	scmd->request_bufflen = be32_to_cpu(hdr->data_length);
	scmd->SCp.ptr = (void *) ctask;
	scmd->done = NULL;

	switch (hdr->flags & ISCSI_FLAG_CMD_ATTR_MASK) {
	case ISCSI_ATTR_UNTAGGED:
	case ISCSI_ATTR_SIMPLE:
		scmd->tag = MSG_SIMPLE_TAG;
		break;
	case ISCSI_ATTR_HEAD_OF_QUEUE:
		scmd->tag = MSG_HEAD_TAG;
		break;
	case ISCSI_ATTR_ORDERED:
	default:
		scmd->tag = MSG_ORDERED_TAG;
	}
	scsi_tgt_queue_command(scmd, (struct scsi_lun *) hdr->lun, hdr->itt);
}

/* TODO: we cannot handle multiple outstanding r2t. */
static void iscsi_r2t_build(struct iscsi_cmd_task *ctask)
{
	struct iscsi_session *session = ctask->conn->session;
	struct iscsi_tcp_cmd_task *tcp_ctask = ctask->dd_data;
	struct iscsi_r2t_rsp *hdr =
		(struct iscsi_r2t_rsp *) &tcp_ctask->unsol_dtask.hdr;
	int length;

	tcp_ctask->xmstate = XMSTATE_R_HDR;
	memset(hdr, 0, sizeof(struct iscsi_hdr));
	iscsi_buf_init_iov(&tcp_ctask->headbuf, (char *)hdr,
			   sizeof(struct iscsi_hdr));

	hdr->opcode = ISCSI_OP_R2T;
	hdr->flags = ISCSI_FLAG_CMD_FINAL;
	memcpy(hdr->lun, ctask->hdr->lun, sizeof(hdr->lun));
	hdr->itt = ctask->itt;
	hdr->r2tsn = cpu_to_be32(tcp_ctask->exp_r2tsn++);
	hdr->data_offset = cpu_to_be32(tcp_ctask->data_offset);
	hdr->ttt = (unsigned long) ctask; /* FIXME */
	length = min(tcp_ctask->r2t_data_count, session->max_burst);
	hdr->data_length = cpu_to_be32(length);
	tcp_ctask->r2t_data_count -= length;

	dprintk("%p %u %u %u %u\n", ctask, length, tcp_ctask->r2t_data_count,
		tcp_ctask->data_offset,	session->max_burst);
}

static void __iscsi_tgt_cmd_exec(struct iscsi_cmd_task *ctask)
{
	u8 opcode = ctask->hdr->opcode & ISCSI_OPCODE_MASK;

	dprintk("%p,%x,%u\n", ctask, opcode, ctask->hdr->cmdsn);
	switch (opcode) {
	case ISCSI_OP_SCSI_CMD:
		if (ctask->sc)
			ctask->sc->done(ctask->sc);
		else
			iscsi_tcp_tgt_sc_queue(ctask);
		break;
	case ISCSI_OP_LOGOUT:
		/* TODO: move to user-space */
		iscsi_tcp_tgt_ctask_xmitqueue(ctask);
		break;
	case ISCSI_OP_NOOP_OUT:
	case ISCSI_OP_SCSI_TMFUNC:
	case ISCSI_OP_TEXT:
	case ISCSI_OP_SNACK:
		BUG_ON(1);
		break;
	default:
		eprintk("unexpected cmnd op %x\n", ctask->hdr->opcode);
		break;
	}
}

static void iscsi_tgt_cmd_exec(struct iscsi_cmd_task *ctask)
{
	struct iscsi_cmd_task *pos;
	struct iscsi_conn *conn = ctask->conn;
	struct iscsi_session *session = conn->session;
	struct iscsi_cls_session *cls_session = session_to_cls(session);
	struct istgt_session *istgt_session = cls_session->dd_data;

	if (ctask->hdr->opcode & ISCSI_OP_IMMEDIATE) {
		__iscsi_tgt_cmd_exec(ctask);
		return;
	}

	spin_lock_bh(&session->lock);

	list_for_each_entry(pos, &istgt_session->cmd_pending, pending)
		if (before(ctask->hdr->cmdsn, pos->hdr->cmdsn))
			break;
	list_add_tail(&ctask->pending, &pos->pending);

retry:
	while (!list_empty(&istgt_session->cmd_pending)) {
		ctask = list_entry(istgt_session->cmd_pending.next,
				   struct iscsi_cmd_task, pending);

		dprintk("%p %x %x\n", ctask, ctask->hdr->cmdsn, session->exp_cmdsn);
		if (be32_to_cpu(ctask->hdr->cmdsn) != session->exp_cmdsn)
			break;

		list_del_init(&ctask->pending);

		spin_unlock_bh(&session->lock);
		session->exp_cmdsn++;
		__iscsi_tgt_cmd_exec(ctask);
		spin_lock_bh(&session->lock);
		goto retry;
	}
	spin_unlock_bh(&session->lock);
}

static struct iscsi_cmd_task *iscsi_tcp_tgt_cmd_init(struct iscsi_conn *conn)
{
	struct iscsi_cmd_task *ctask;
	struct iscsi_tcp_conn *tcp_conn = conn->dd_data;
	struct iscsi_session *session = conn->session;
	struct iscsi_tcp_cmd_task *tcp_ctask;
	struct iscsi_hdr *hdr = tcp_conn->in.hdr;

	__kfifo_get(session->cmdpool.queue, (void*)&ctask, sizeof(void*));
	BUG_ON(!ctask);

	ctask->conn = conn;
	ctask->data_count = 0;
	ctask->sc = NULL;
	ctask->datasn = 0;
	ctask->itt = hdr->itt;
	INIT_LIST_HEAD(&ctask->running);
	INIT_LIST_HEAD(&ctask->hash);
	INIT_LIST_HEAD(&ctask->pending);
	memcpy(ctask->hdr, hdr, sizeof(*hdr));
	ctask->total_length = be32_to_cpu(ctask->hdr->data_length);

	tcp_ctask = ctask->dd_data;
	tcp_ctask->sg = NULL;
	tcp_ctask->sent = 0;
	tcp_ctask->data_offset = 0;

	if (hdr->flags & ISCSI_FLAG_CMD_WRITE) {
		tcp_ctask->exp_r2tsn = 0;
		tcp_ctask->r2t_data_count = be32_to_cpu(ctask->hdr->data_length)
			- tcp_conn->in.datalen;
		if (hdr->flags & ISCSI_FLAG_CMD_FINAL)
			ctask->unsol_count = 0;
		else
			ctask->unsol_count = 1;

		ctask->data_count = ctask->imm_count = tcp_conn->in.datalen;
		dprintk("%p %x %u %u %u %u\n", ctask, hdr->flags,
			tcp_ctask->r2t_data_count,
			ctask->unsol_count,
			ctask->total_length,
			ctask->imm_count);

		hashlist_add(session_to_cls(session), ctask);

		/* we stop reading here. */
		set_bit(ISCSI_SUSPEND_BIT, &conn->suspend_rx);
		iscsi_tcp_tgt_sc_queue(ctask);
	} else
		iscsi_tgt_cmd_exec(ctask);

	return ctask;
}

static int iscsi_tcp_tgt_hdr_recv(struct iscsi_conn *conn)
{
	int rc, opcode;
	struct iscsi_hdr *hdr;
	struct iscsi_tcp_conn *tcp_conn = conn->dd_data;
	struct iscsi_cmd_task *ctask = NULL;
	struct iscsi_session *session = conn->session;
	struct iscsi_cls_session *cls_session = session_to_cls(session);

	rc = iscsi_tcp_hdr_recv(conn);
	if (rc)
		return rc;

	hdr = tcp_conn->in.hdr;
	opcode = hdr->opcode & ISCSI_OPCODE_MASK;
	dprintk("opcode 0x%x offset %d copy %d ahslen %d datalen %d\n",
		opcode, tcp_conn->in.offset, tcp_conn->in.copy,
		hdr->hlength << 2, tcp_conn->in.datalen);

	switch (opcode) {
	case ISCSI_OP_LOGOUT:
	case ISCSI_OP_SCSI_CMD:
		ctask = iscsi_tcp_tgt_cmd_init(conn);
		dprintk("%p\n", ctask);
		break;
	case ISCSI_OP_SCSI_DATA_OUT:
		ctask = hashlist_find(cls_session, hdr->itt);
		if (!ctask) {
			eprintk("Cannot find %x\n", ctask->hdr->itt);
			rc = ISCSI_ERR_NO_SCSI_CMD;
			break;
		}
		ctask->data_count = tcp_conn->in.datalen;
		{
			struct iscsi_tcp_cmd_task *tcp_ctask = ctask->dd_data;
			struct iscsi_data *hdr = (struct iscsi_data *) hdr;
			dprintk("%p %u %u %u %u %u %x\n", ctask,
				ctask->total_length,
				be32_to_cpu(hdr->offset),
				tcp_ctask->data_offset,
				tcp_ctask->r2t_data_count, ctask->data_count,
				tcp_conn->in.hdr->flags);
		}
		break;
	case ISCSI_OP_NOOP_OUT:
	case ISCSI_OP_SCSI_TMFUNC:
		eprintk("Cannot handle yet %x\n", opcode);
		break;
	case ISCSI_OP_TEXT:
	case ISCSI_OP_SNACK:
	default:
		rc = ISCSI_ERR_BAD_OPCODE;
	}
	tcp_conn->in.ctask = ctask;

	return rc;
}

static void iscsi_cmd_data_done(struct iscsi_cmd_task *ctask)
{
	struct iscsi_tcp_cmd_task *tcp_ctask = ctask->dd_data;

	if (tcp_ctask->r2t_data_count) {
		iscsi_r2t_build(ctask);
		iscsi_tcp_tgt_ctask_xmitqueue(ctask);
	} else
		iscsi_tgt_cmd_exec(ctask);
}

static void iscsi_handle_data_out_cmd(struct iscsi_conn *conn)
{
	struct iscsi_tcp_conn *tcp_conn = conn->dd_data;
	struct iscsi_cmd_task *ctask = tcp_conn->in.ctask;
	struct iscsi_tcp_cmd_task *tcp_ctask = ctask->dd_data;
	struct iscsi_hdr *hdr = (struct iscsi_hdr *) ctask->hdr;

	BUG_ON(ctask->data_count);
	tcp_ctask->data_offset += ntoh24(hdr->dlength);

	dprintk("%p %x %u %u %u %u %u\n", ctask, hdr->flags,
		tcp_ctask->r2t_data_count, ctask->unsol_count,
		ctask->total_length, ctask->imm_count, tcp_ctask->data_offset);

	if (hdr->ttt == cpu_to_be32(ISCSI_RESERVED_TAG)) {
		tcp_ctask->r2t_data_count -= ntoh24(hdr->dlength);
		if (hdr->flags & ISCSI_FLAG_CMD_FINAL) {
			ctask->unsol_count = 0;
			iscsi_cmd_data_done(ctask);
		}
	} else {
		if (hdr->flags & ISCSI_FLAG_CMD_FINAL)
			iscsi_cmd_data_done(ctask);
	}
}

static int iscsi_tcp_tgt_data_recv(struct iscsi_conn *conn)
{
	struct iscsi_tcp_conn *tcp_conn = conn->dd_data;
	struct iscsi_cmd_task *ctask = tcp_conn->in.ctask;
	struct iscsi_cmd *hdr = ctask->hdr;
	int rc = 0, opcode;

	opcode = hdr->opcode & ISCSI_OPCODE_MASK;
	dprintk("opcode 0x%x offset %d copy %d datalen %d\n",
		opcode, tcp_conn->in.offset, tcp_conn->in.copy,
		tcp_conn->in.datalen);

	switch (opcode) {
	case ISCSI_OP_SCSI_CMD:
		rc = iscsi_scsi_data_in(conn);
		if (!rc) {
			struct iscsi_tcp_cmd_task *tcp_ctask = ctask->dd_data;

			dprintk("%p %x %u %u %u %u %u\n", ctask,
				hdr->flags,
				tcp_ctask->r2t_data_count,
				ctask->unsol_count,
				ctask->total_length,
				ctask->imm_count, tcp_ctask->data_offset);

			tcp_ctask->data_offset += ctask->imm_count;
			ctask->imm_count = 0;
			if (!ctask->unsol_count)
				iscsi_cmd_data_done(ctask);
		}
		break;
	case ISCSI_OP_SCSI_DATA_OUT:
		rc = iscsi_scsi_data_in(conn);
		if (!rc)
			iscsi_handle_data_out_cmd(conn);
		break;
	case ISCSI_OP_TEXT:
	case ISCSI_OP_LOGOUT:
	case ISCSI_OP_NOOP_OUT:
	case ISCSI_OP_ASYNC_EVENT:
	default:
		BUG_ON(1);
	}

	return rc;
}

static void __iscsi_data_rsp_build(struct iscsi_cmd_task *ctask,
				   struct iscsi_data_rsp *hdr)
{
	struct iscsi_tcp_cmd_task *tcp_ctask = ctask->dd_data;
	struct scsi_cmnd *sc = ctask->sc;
	struct iscsi_session *session = ctask->conn->session;
	u32 left, residual, exp_datalen, size;

	exp_datalen = be32_to_cpu(ctask->hdr->data_length);
	left = min_t(int, ctask->unsol_count, exp_datalen);

	hdr->opcode = ISCSI_OP_SCSI_DATA_IN;
	hdr->itt = ctask->itt;
	hdr->ttt = cpu_to_be32(ISCSI_RESERVED_TAG);
	hdr->offset = cpu_to_be32(sc->offset + tcp_ctask->data_offset);
	hdr->statsn = cpu_to_be32(ctask->conn->exp_statsn++);
	hdr->exp_cmdsn = cpu_to_be32(session->exp_cmdsn);
	hdr->max_cmdsn = cpu_to_be32(session->exp_cmdsn + session->cmds_max / 2);
	hdr->datasn = cpu_to_be32(ctask->datasn++);

	if (left <= ctask->conn->max_xmit_dlength) {
		hdr->flags = ISCSI_FLAG_CMD_FINAL | ISCSI_FLAG_DATA_STATUS;

		if (sc->request_bufflen < exp_datalen) {
			hdr->flags |= ISCSI_FLAG_CMD_UNDERFLOW;
			residual = exp_datalen - sc->request_bufflen;
		} else if (sc->request_bufflen > exp_datalen) {
			hdr->flags |= ISCSI_FLAG_CMD_OVERFLOW;
			residual = sc->request_bufflen - exp_datalen;
		} else
			residual = 0;
		hdr->residual_count = cpu_to_be32(residual);
		size = left;
	} else
		size = ctask->conn->max_xmit_dlength;

	dprintk("%d %d %d %d %d\n", size, left, ctask->conn->max_xmit_dlength,
		exp_datalen, sc->request_bufflen);

	hton24(hdr->dlength, size);
	ctask->data_count = ctask->unsol_count = size;
	tcp_ctask->data_offset += size;
}

static void __iscsi_rsp_build(struct iscsi_cmd_task *ctask,
			      struct iscsi_hdr *p)
{
	struct iscsi_tcp_cmd_task *tcp_ctask = ctask->dd_data;
	struct iscsi_session *session = ctask->conn->session;
	u8 opcode = ctask->hdr->opcode & ISCSI_OPCODE_MASK;

	dprintk("%p %x\n", ctask, opcode);
	ctask->data_count = 0;
	tcp_ctask->xmstate = XMSTATE_R_HDR;

	switch (opcode) {
	case ISCSI_OP_SCSI_CMD:
	{
		struct iscsi_cmd_rsp *hdr = (struct iscsi_cmd_rsp *) p;

		hdr->opcode = ISCSI_OP_SCSI_CMD_RSP;
		hdr->itt = ctask->itt;
		hdr->flags = ISCSI_FLAG_CMD_FINAL;
		hdr->response = ISCSI_STATUS_CMD_COMPLETED;
		hdr->cmd_status = SAM_STAT_GOOD;
		hdr->statsn = cpu_to_be32(ctask->conn->exp_statsn++);
		hdr->exp_cmdsn = cpu_to_be32(session->exp_cmdsn);
		hdr->max_cmdsn =
			cpu_to_be32(session->exp_cmdsn + session->cmds_max / 2);
		break;
	}
	case ISCSI_OP_LOGOUT:
	{
		struct iscsi_logout_rsp *hdr = (struct iscsi_logout_rsp *) p;
		hdr->opcode = ISCSI_OP_LOGOUT_RSP;
		hdr->flags = ISCSI_FLAG_CMD_FINAL;
		hdr->itt = ctask->itt;
		break;
	}
	default:
		BUG_ON(1);
		break;
	}
	dprintk("%p %x\n", ctask, opcode);
}

static void iscsi_data_rsp_build(struct iscsi_conn *conn,
				 struct iscsi_cmd_task *ctask)
{
	struct iscsi_tcp_cmd_task *tcp_ctask = ctask->dd_data;
	struct iscsi_data_task *dtask;

	dprintk("%p\n", ctask);
	dtask = tcp_ctask->dtask = &tcp_ctask->unsol_dtask;
	memset(&dtask->hdr, 0, sizeof(struct iscsi_hdr));
	iscsi_buf_init_iov(&tcp_ctask->headbuf, (char*)&dtask->hdr,
			   sizeof(struct iscsi_hdr));
	__iscsi_data_rsp_build(ctask, (struct iscsi_data_rsp *) &dtask->hdr);
}

static void iscsi_rsp_build(struct iscsi_conn *conn,
			    struct iscsi_cmd_task *ctask)
{
	struct iscsi_tcp_cmd_task *tcp_ctask = ctask->dd_data;
	struct iscsi_data_task *dtask;

	dprintk("%p\n", ctask);
	dtask = tcp_ctask->dtask = &tcp_ctask->unsol_dtask;
	memset(&dtask->hdr, 0, sizeof(struct iscsi_hdr));
	iscsi_buf_init_iov(&tcp_ctask->headbuf, (char*)&dtask->hdr,
			   sizeof(struct iscsi_hdr));
	__iscsi_rsp_build(ctask, (struct iscsi_hdr *) &dtask->hdr);
}

static int iscsi_tgt_transfer_response(struct scsi_cmnd *scmd,
				       void (*done)(struct scsi_cmnd *))
{
	struct iscsi_cmd_task *ctask = (struct iscsi_cmd_task *) scmd->SCp.ptr;

	dprintk("%p %x %x %u %u\n", ctask, ctask->hdr->opcode & ISCSI_OPCODE_MASK,
		ctask->hdr->cdb[0], scmd->request_bufflen, scmd->sc_data_direction);

	if (scmd->sc_data_direction == DMA_FROM_DEVICE && scmd->request_bufflen) {
		/* We've already sent data in transfer_data. */
		iscsi_tcp_tgt_ctask_cleanup(ctask);
		done(scmd);
	} else {
		scmd->done = done;
		iscsi_rsp_build(ctask->conn, ctask);
		iscsi_tcp_tgt_ctask_xmitqueue(ctask);
	}
	return 0;
}

static void recvworker(void *data)
{
	struct iscsi_conn *conn = data;
	struct iscsi_tcp_conn *tcp_conn = conn->dd_data;
	struct sock *sk = tcp_conn->sock->sk;

	lock_sock(sk);
	sk->sk_data_ready(sk, 0);
	release_sock(sk);
}

static int iscsi_tgt_transfer_data(struct scsi_cmnd *sc,
				   void (*done)(struct scsi_cmnd *))
{
	struct iscsi_cmd_task *ctask = (struct iscsi_cmd_task *) sc->SCp.ptr;
	struct iscsi_tcp_cmd_task *tcp_ctask = ctask->dd_data;

	dprintk("%p %x %x %u %u\n", ctask, ctask->hdr->opcode & ISCSI_OPCODE_MASK,
		ctask->hdr->cdb[0], sc->request_bufflen, sc->sc_data_direction);

	/* We cannot handle this. */
	BUG_ON(sc->offset);

	sc->done = done;
	if (sc->sc_data_direction == DMA_TO_DEVICE) {
		struct iscsi_tcp_conn *tcp_conn = ctask->conn->dd_data;

		if (!ctask->unsol_count && !ctask->imm_count)
			iscsi_cmd_data_done(ctask);

		clear_bit(ISCSI_SUSPEND_BIT, &ctask->conn->suspend_rx);
		INIT_WORK(&tcp_conn->recvwork, recvworker, ctask->conn);
		queue_work(recvwq, &tcp_conn->recvwork);
	} else {
		tcp_ctask->sg_count = 0;
		tcp_ctask->data_offset = 0;
		ctask->unsol_count = sc->request_bufflen;
		tcp_ctask->sg = sc->request_buffer;
		tcp_ctask->xmstate = XMSTATE_UNS_INIT | XMSTATE_UNS_HDR;
		iscsi_tcp_tgt_ctask_xmitqueue(ctask);
	}
	return 0;
}

static int iscsi_tgt_eh_abort_handler(struct scsi_cmnd *scmd)
{
	BUG_ON(1);
	return 0;
}

static int iscsi_tcp_tgt_ctask_xmit(struct iscsi_conn *conn,
				    struct iscsi_cmd_task *ctask)
{
	struct iscsi_tcp_cmd_task *tcp_ctask = ctask->dd_data;
	struct scsi_cmnd *sc = ctask->sc;
	int err;

	dprintk("%p\n", ctask);

	err = iscsi_tcp_ctask_xmit(conn, ctask);
	if (err)
		return err;

	dprintk("%p %d\n", ctask, err);

	switch (ctask->hdr->opcode & ISCSI_OPCODE_MASK) {
	case ISCSI_OP_LOGOUT:
		iscsi_tcp_tgt_ctask_cleanup(ctask);
		break;
	case ISCSI_OP_SCSI_CMD:
	{
		struct iscsi_hdr *hdr =
			(struct iscsi_hdr *) &tcp_ctask->unsol_dtask.hdr;
		u8 opcode = hdr->opcode & ISCSI_OPCODE_MASK;

		switch (opcode) {
		case ISCSI_OP_SCSI_CMD_RSP:
			iscsi_tcp_tgt_ctask_cleanup(ctask);
			sc->done(sc);
			break;
		case ISCSI_OP_SCSI_DATA_IN:
			sc->done(sc);
			break;
		}
	}
	default:
		break;
	}

	dprintk("%p %d\n", ctask, err);

	return err;
}

static struct iscsi_cls_session *
iscsi_tcp_tgt_session_create(struct iscsi_transport *iscsit,
			     struct scsi_transport_template *scsit,
			     uint32_t initial_cmdsn, uint32_t *hostno)
{
	struct Scsi_Host *shost;
	struct iscsi_cls_session *cls_session;
	struct iscsi_session *session;
	struct istgt_session *istgt_session;
	int i, err;

	dprintk("%u %u\n", initial_cmdsn, *hostno);
	cls_session = iscsi_tcp_session_create(iscsit, scsit, initial_cmdsn, hostno);
	if (!cls_session)
		return NULL;
	shost = iscsi_session_to_shost(cls_session);
	err = scsi_tgt_alloc_queue(shost);
	if (err)
		goto session_free;

	session = class_to_transport_session(cls_session);
	for (i = 0; i < initial_cmdsn; i++) {
		struct iscsi_cmd_task *ctask = session->cmds[i];
		INIT_LIST_HEAD(&ctask->hash);
		INIT_LIST_HEAD(&ctask->pending);
	}
	session->exp_cmdsn = initial_cmdsn;

	istgt_session =	(struct istgt_session *) cls_session->dd_data;
	INIT_LIST_HEAD(&istgt_session->cmd_hash);
	INIT_LIST_HEAD(&istgt_session->cmd_pending);

	dprintk("%u %u\n", initial_cmdsn, *hostno);

	return cls_session;
session_free:
	iscsi_session_teardown(cls_session);
	return NULL;
}

static struct iscsi_tcp_operations iscsi_tcp_tgt_ops = {
	.hdr_recv		= iscsi_tcp_tgt_hdr_recv,
	.data_recv		= iscsi_tcp_tgt_data_recv,
	.unsolicit_data_init	= iscsi_data_rsp_build,
};

static struct iscsi_cls_conn *
iscsi_tcp_tgt_conn_create(struct iscsi_cls_session *cls_session,
			  uint32_t conn_idx)
{
	struct iscsi_cls_conn *cls_conn;
	dprintk("%u\n", conn_idx);
	cls_conn = iscsi_tcp_conn_create(cls_session, conn_idx,
					 &iscsi_tcp_tgt_ops);
	dprintk("%u %p\n", conn_idx, cls_conn->dd_data);
	return cls_conn;
}

#define	DEFAULT_NR_QUEUED_CMNDS	32
#define TGT_NAME "iscsi_tcp_tgt"

static struct scsi_host_template iscsi_tcp_tgt_sht = {
	.name			= TGT_NAME,
	.module			= THIS_MODULE,
	.can_queue		= DEFAULT_NR_QUEUED_CMNDS,
	.sg_tablesize		= SG_ALL,
	.max_sectors		= 65535,
	.use_clustering		= DISABLE_CLUSTERING,
	.transfer_response	= iscsi_tgt_transfer_response,
	.transfer_data		= iscsi_tgt_transfer_data,
	.eh_abort_handler	= iscsi_tgt_eh_abort_handler,
};

static struct iscsi_transport iscsi_tcp_tgt_transport = {
	.owner			= THIS_MODULE,
	.name			= TGT_NAME,
	.host_template		= &iscsi_tcp_tgt_sht,
	.conndata_size		= sizeof(struct iscsi_conn),
	.sessiondata_size	= sizeof(struct istgt_session),
	.max_conn		= 1,
	.max_cmd_len		= ISCSI_TCP_MAX_CMD_LEN,
	.create_session		= iscsi_tcp_tgt_session_create,
	.destroy_session	= iscsi_tcp_session_destroy,
	.create_conn		= iscsi_tcp_tgt_conn_create,
	.destroy_conn		= iscsi_tcp_conn_destroy,
	.bind_conn		= iscsi_tcp_conn_bind,
	.start_conn		= iscsi_conn_start,
	.set_param		= iscsi_conn_set_param,
	.terminate_conn		= iscsi_tcp_terminate_conn,
	.xmit_cmd_task		= iscsi_tcp_tgt_ctask_xmit,
};

static int __init iscsi_tcp_tgt_init(void)
{
	printk("iSCSI Target over TCP\n");

	recvwq = create_workqueue("iscsi_recvwork");
	if (!recvwq)
		return -ENOMEM;

	if (!iscsi_register_transport(&iscsi_tcp_tgt_transport))
		goto destroy_wq;

	return 0;
destroy_wq:
	destroy_workqueue(recvwq);
	return -ENODEV;
}

static void __exit iscsi_tcp_tgt_exit(void)
{
	destroy_workqueue(recvwq);
	iscsi_unregister_transport(&iscsi_tcp_tgt_transport);
}

module_init(iscsi_tcp_tgt_init);
module_exit(iscsi_tcp_tgt_exit);

MODULE_DESCRIPTION("iSCSI/TCP target");
MODULE_LICENSE("GPL");
