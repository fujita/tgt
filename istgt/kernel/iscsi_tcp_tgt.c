/*
 * iSCSI Target over TCP/IP
 *
 * Copyright (C) 2004 Dmitry Yusupov
 * Copyright (C) 2004 Alex Aizman
 * Copyright (C) 2005 - 2006 Mike Christie
 * Copyright (C) 2006 Red Hat, Inc.  All rights reserved.
 * Copyright (C) 2006 FUJITA Tomonori <tomof@acm.org>
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

/*
 * Most part is taken from iscsi_tcp. Integrating with iscsi_tcp would
 * be nice...
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
#include <iscsi_tcp.h>
#include <scsi/libiscsi.h>
#include <scsi/scsi_tgt.h>
#include <scsi/scsi_tcq.h>
#include "scsi_transport_iscsi.h"
#include "iscsi_tcp_priv.h"

/* tmp - will replace with SCSI logging stuff */
#define eprintk(fmt, args...)					\
do {								\
	printk("%s(%d) " fmt, __FUNCTION__, __LINE__, ##args);	\
} while (0)

#define dprintk eprintk

struct istgt_session {
	struct list_head recvlist;
	/* replace with array later on */
	struct list_head cmd_hash;
	spinlock_t slock;
	struct work_struct recvwork;
};

struct istgt_task {
	struct list_head hash;
	struct list_head tlist;
};

static kmem_cache_t *taskcache;

static inline struct istgt_task *ctask_to_ttask(struct iscsi_cmd_task *ctask)
{
	return (struct istgt_task *) ((void *) ctask->dd_data +
				      sizeof(struct iscsi_tcp_cmd_task));
}

static inline struct iscsi_cmd_task *ttask_to_ctask(struct istgt_task *ttask)
{
	return (struct iscsi_cmd_task *)
		((void *) ttask - sizeof(struct iscsi_tcp_cmd_task));
}

static void build_r2t(struct iscsi_cmd_task *ctask)
{
	struct iscsi_r2t_rsp *hdr;
	struct iscsi_data_task *dtask;
	struct iscsi_r2t_info *r2t;
/* 	struct iscsi_session *session = ctask->conn->session; */
	struct iscsi_tcp_cmd_task *tcp_ctask = ctask->dd_data;
/* 	struct iscsi_tcp_conn *tcp_conn = ctask->conn->dd_data; */
	int rc;

/* 	length = req->r2t_length; */
/* 	burst = req->conn->session->param.max_burst_length; */
/* 	offset = be32_to_cpu(cmd_hdr(req)->data_length) - length; */
/* more: */
	rc = __kfifo_get(tcp_ctask->r2tpool.queue, (void*)&r2t, sizeof(void*));
	BUG_ON(!rc);

	dtask = mempool_alloc(tcp_ctask->datapool, GFP_ATOMIC);
	BUG_ON(!dtask);

	INIT_LIST_HEAD(&dtask->item);
	r2t->dtask = dtask;
	hdr = (struct iscsi_r2t_rsp *) &dtask->hdr;

/* 	rsp->pdu.bhs.ttt = req->target_task_tag; */

	hdr->opcode = ISCSI_OP_R2T;
	hdr->flags = ISCSI_FLAG_CMD_FINAL;
	memcpy(hdr->lun, ctask->hdr->lun, 8);
	hdr->itt = ctask->hdr->itt;
	hdr->r2tsn = cpu_to_be32(tcp_ctask->exp_r2tsn++);
/* 	hdr->data_offset = cpu_to_be32(offset); */
/* 	if (length > burst) { */
/* 		rsp_hdr->data_length = cpu_to_be32(burst); */
/* 		length -= burst; */
/* 		offset += burst; */
/* 	} else { */
/* 		rsp_hdr->data_length = cpu_to_be32(length); */
/* 		length = 0; */
/* 	} */

	dprintk("%x %u %u %u\n", ctask->hdr->itt,
		be32_to_cpu(hdr->data_length),
		be32_to_cpu(hdr->data_offset),
		be32_to_cpu(hdr->r2tsn));

/* 	if (++req->outstanding_r2t >= req->conn->session->param.max_outstanding_r2t) */
/* 		break; */

	__kfifo_put(tcp_ctask->r2tpool.queue, (void*)&r2t, sizeof(void*));

/* 	if (length) */
/* 		goto more; */
}

static void istgt_scsi_tgt_queue_command(struct iscsi_cmd_task *ctask)
{
	struct iscsi_session *session = ctask->conn->session;
	struct iscsi_cls_session *cls_session = session_to_cls(session);
	struct Scsi_Host *shost = iscsi_session_to_shost(cls_session);
	struct iscsi_cmd *hdr = ctask->hdr;
	struct scsi_cmnd *scmd;
	enum dma_data_direction dir;

	if (hdr->flags & ISCSI_FLAG_CMD_WRITE)
		dir = DMA_TO_DEVICE;
	else if (hdr->flags & ISCSI_FLAG_CMD_READ)
		dir = DMA_FROM_DEVICE;
	else
		dir = DMA_NONE;

	scmd = scsi_host_get_command(shost, dir, GFP_KERNEL);
	BUG_ON(!scmd);
	ctask->sc = scmd;

	memcpy(scmd->data_cmnd, hdr->cdb, MAX_COMMAND_SIZE);
	scmd->request_bufflen = be32_to_cpu(hdr->data_length);
	scmd->SCp.ptr = (void *) ctask;

	switch (hdr->flags & ISCSI_FLAG_CMD_ATTR_MASK) {
	case ISCSI_ATTR_UNTAGGED:
	case ISCSI_ATTR_SIMPLE:
		scmd->tag = MSG_SIMPLE_TAG;
		break;
	case ISCSI_ATTR_ORDERED:
		scmd->tag = MSG_ORDERED_TAG;
		break;
	case ISCSI_ATTR_HEAD_OF_QUEUE:
		scmd->tag = MSG_HEAD_TAG;
		break;
	case ISCSI_ATTR_ACA:
		scmd->tag = MSG_SIMPLE_TAG;
		break;
	default:
		scmd->tag = MSG_SIMPLE_TAG;
	}

	if (scmd->sc_data_direction == DMA_TO_DEVICE &&
	    be32_to_cpu(hdr->data_length)) {
		switch (hdr->cdb[0]) {
		case WRITE_6:
		case WRITE_10:
		case WRITE_16:
		case WRITE_VERIFY:
			break;
		default:
			eprintk("%x\n", hdr->cdb[0]);
			break;
		}
	}

	scsi_tgt_queue_command(scmd, (struct scsi_lun *) hdr->lun, hdr->itt);
}

static void istgt_scsi_cmnd_exec(struct iscsi_cmd_task *ctask)
{
	struct scsi_cmnd *scmd = ctask->sc;

	if (ctask->data_count) {
		if (!ctask->unsol_count)
			;
/* 			send_r2t(ctask); */
	} else {
/* 		set_cmd_waitio(cmnd); */
		if (scmd) {
/* 			BUG_ON(!ctask->done); */
/* 			cmnd->done(scmd); */
		} else
			istgt_scsi_tgt_queue_command(ctask);
	}
}

static void istgt_cmd_exec(struct iscsi_cmd_task *ctask)
{
	u8 opcode;

	opcode = ctask->hdr->opcode & ISCSI_OPCODE_MASK;

	dprintk("%p,%x,%u\n", ctask, opcode, ctask->hdr->cmdsn);

	switch (opcode) {
	case ISCSI_OP_NOOP_OUT:
/* 		noop_out_exec(cmnd); */
		break;
	case ISCSI_OP_SCSI_CMD:
		istgt_scsi_cmnd_exec(ctask);
		break;
	case ISCSI_OP_SCSI_TMFUNC:
/* 		execute_task_management(cmnd); */
		break;
	case ISCSI_OP_LOGOUT:
/* 		logout_exec(cmnd); */
		break;
/* 	case ISCSI_OP_SCSI_REJECT: */
/* 		iscsi_cmnd_init_write(get_rsp_cmnd(cmnd)); */
/* 		break; */
	case ISCSI_OP_TEXT:
	case ISCSI_OP_SNACK:
		break;
	default:
		eprintk("unexpected cmnd op %x\n", ctask->hdr->opcode);
		break;
	}
}

static void istgt_recvworker(void *data)
{
	struct iscsi_cls_session *cls_session = data;
	struct iscsi_session *session =
		class_to_transport_session(cls_session);
	struct istgt_session *istgt_session =
		(struct istgt_session *) cls_session->dd_data;
	struct iscsi_cmd_task *ctask;
	struct istgt_task *pos;

retry:
	spin_lock_bh(&istgt_session->slock);

	while (istgt_session->recvlist.next) {
		pos = list_entry(istgt_session->recvlist.next,
				 struct istgt_task, tlist);
		ctask = ttask_to_ctask(pos);
		if (ctask->hdr->cmdsn != session->exp_cmdsn)
			break;

		list_del(&pos->tlist);
		session->exp_cmdsn++;

		spin_unlock_bh(&istgt_session->slock);
		istgt_cmd_exec(ctask);
		goto retry;
	}

	spin_unlock_bh(&istgt_session->slock);
}

static void istgt_ctask_recvlist_add(struct iscsi_cmd_task *ctask)
{
	struct iscsi_session *session = ctask->conn->session;
	struct iscsi_cls_session *cls_session = session_to_cls(session);
	struct istgt_session *istgt_session;
	struct istgt_task *pos;

	istgt_session = (struct istgt_session *) cls_session->dd_data;

	spin_lock_bh(&istgt_session->slock);

	if (ctask->hdr->opcode & ISCSI_OP_IMMEDIATE) {
		list_add(&ctask_to_ttask(ctask)->tlist,
			 &istgt_session->recvlist);
		goto out;
	}

	list_for_each_entry(pos, &istgt_session->recvlist, tlist)
		if (before(ctask->hdr->cmdsn, ttask_to_ctask(pos)->hdr->cmdsn))
			break;

	list_add_tail(&ctask_to_ttask(ctask)->tlist, &pos->tlist);
out:
	spin_unlock_bh(&istgt_session->slock);
}

static int
istgt_tcp_ctask_xmit(struct iscsi_conn *conn, struct iscsi_mgmt_task *mtask)
{
	return 0;
}

static void istgt_unsolicited_data(struct iscsi_cmd_task *ctask)
{
/* 	struct iscsi_tcp_cmd_task *tcp_ctask = ctask->dd_data; */

	istgt_scsi_tgt_queue_command(ctask);
/* 	tcp_ctask->r2t_data_count; */
/* 	ctask->r2t_data_count; */
}

/*
 * the followings are taken from iscsi_tcp.
 */

int iscsi_tcp_hdr_recv(struct iscsi_conn *conn)
{
	int rc = 0, opcode, ahslen;
	struct iscsi_hdr *hdr;
	struct iscsi_session *session = conn->session;
	struct iscsi_cls_session *cls_session = session_to_cls(session);
	struct iscsi_tcp_conn *tcp_conn = conn->dd_data;
	struct Scsi_Host *shost;
	uint32_t cdgst, rdgst = 0;
	struct iscsi_cmd_task *ctask = NULL;

	shost = iscsi_session_to_shost(cls_session);
	hdr = tcp_conn->in.hdr;

	/* verify PDU length */
	tcp_conn->in.datalen = ntoh24(hdr->dlength);
	if (tcp_conn->in.datalen > conn->max_recv_dlength) {
		printk(KERN_ERR "iscsi_tcp: datalen %d > %d\n",
		       tcp_conn->in.datalen, conn->max_recv_dlength);
		return ISCSI_ERR_DATALEN;
	}
	tcp_conn->data_copied = 0;

	/* read AHS */
	ahslen = hdr->hlength << 2;
	tcp_conn->in.offset += ahslen;
	tcp_conn->in.copy -= ahslen;
	if (tcp_conn->in.copy < 0) {
		printk(KERN_ERR "iscsi_tcp: can't handle AHS with length "
		       "%d bytes\n", ahslen);
		return ISCSI_ERR_AHSLEN;
	}

	/* calculate read padding */
	tcp_conn->in.padding = tcp_conn->in.datalen & (ISCSI_PAD_LEN-1);
	if (tcp_conn->in.padding) {
		tcp_conn->in.padding = ISCSI_PAD_LEN - tcp_conn->in.padding;
		dprintk("read padding %d bytes\n", tcp_conn->in.padding);
	}

	if (conn->hdrdgst_en) {
		struct scatterlist sg;

		sg_init_one(&sg, (u8 *)hdr,
			    sizeof(struct iscsi_hdr) + ahslen);
		crypto_digest_digest(tcp_conn->rx_tfm, &sg, 1, (u8 *)&cdgst);
		rdgst = *(uint32_t*)((char*)hdr + sizeof(struct iscsi_hdr) +
				     ahslen);
		if (cdgst != rdgst) {
			printk(KERN_ERR "iscsi_tcp: hdrdgst error "
			       "recv 0x%x calc 0x%x\n", rdgst, cdgst);
			return ISCSI_ERR_HDR_DGST;
		}
	}

	opcode = hdr->opcode & ISCSI_OPCODE_MASK;
	dprintk("opcode 0x%x offset %d copy %d ahslen %d datalen %d\n",
		opcode, tcp_conn->in.offset, tcp_conn->in.copy,
		ahslen, tcp_conn->in.datalen);

	switch (opcode) {
	case ISCSI_OP_NOOP_OUT:
	case ISCSI_OP_SCSI_CMD:
	case ISCSI_OP_SCSI_TMFUNC:
	case ISCSI_OP_LOGOUT:
		__kfifo_get(session->cmdpool.queue, (void*)&ctask, sizeof(void*));
		ctask->conn = conn;
		memcpy(ctask->hdr, hdr, sizeof(*hdr));
		if (opcode == ISCSI_OP_SCSI_CMD)
			switch (ctask->hdr->cdb[0]) {
			case WRITE_6:
			case WRITE_10:
			case WRITE_16:
			case WRITE_VERIFY:
				istgt_unsolicited_data(ctask);
				set_bit(ISCSI_SUSPEND_BIT, &conn->suspend_rx);
			}
		break;
	case ISCSI_OP_SCSI_DATA_OUT:
		/* Find a command in the hash list */
		/* data_out_start(conn, cmnd); */
		break;
	case ISCSI_OP_TEXT:
	case ISCSI_OP_SNACK:
	default:
		rc = ISCSI_ERR_BAD_OPCODE;
	}

	if (ctask)
		tcp_conn->in.ctask = ctask;
	return rc;
}

static int
iscsi_data_recv(struct iscsi_conn *conn)
{
	struct iscsi_tcp_conn *tcp_conn = conn->dd_data;
	int rc = 0, opcode;

	opcode = tcp_conn->in.hdr->opcode & ISCSI_OPCODE_MASK;
	switch (opcode) {
	case ISCSI_OP_SCSI_CMD:
	case ISCSI_OP_SCSI_DATA_OUT:
		iscsi_scsi_data_in(conn);
		break;
	case ISCSI_OP_TEXT:
	case ISCSI_OP_LOGOUT:
	case ISCSI_OP_NOOP_OUT:
	case ISCSI_OP_ASYNC_EVENT:
		/*
		 * Collect data segment to the connection's data
		 * placeholder
		 */
		if (iscsi_tcp_copy(tcp_conn)) {
			rc = -EAGAIN;
			goto exit;
		}

/* 		rc = iscsi_complete_pdu(conn, tcp_conn->in.hdr, tcp_conn->data, */
/* 					tcp_conn->in.datalen); */
/* 		if (!rc && conn->datadgst_en && opcode != ISCSI_OP_LOGIN_RSP) */
/* 			iscsi_recv_digest_update(tcp_conn, tcp_conn->data, */
/* 			  			tcp_conn->in.datalen); */
		break;
	default:
		BUG_ON(1);
	}
exit:
	return rc;
}

static int
iscsi_tcp_data_recv(read_descriptor_t *rd_desc, struct sk_buff *skb,
		unsigned int offset, size_t len)
{
	int rc;
	struct iscsi_conn *conn = rd_desc->arg.data;
	struct iscsi_tcp_conn *tcp_conn = conn->dd_data;
	int processed;
	char pad[ISCSI_PAD_LEN];
	struct scatterlist sg;

	/*
	 * Save current SKB and its offset in the corresponding
	 * connection context.
	 */
	tcp_conn->in.copy = skb->len - offset;
	tcp_conn->in.offset = offset;
	tcp_conn->in.skb = skb;
	tcp_conn->in.len = tcp_conn->in.copy;
	BUG_ON(tcp_conn->in.copy <= 0);
	dprintk("in %d bytes\n", tcp_conn->in.copy);

more:
	tcp_conn->in.copied = 0;
	rc = 0;

	if (unlikely(conn->suspend_rx)) {
		dprintk("conn %d Rx suspended!\n", conn->id);
		return 0;
	}

	if (tcp_conn->in_progress == IN_PROGRESS_WAIT_HEADER ||
	    tcp_conn->in_progress == IN_PROGRESS_HEADER_GATHER) {
		rc = iscsi_hdr_extract(tcp_conn);
		if (rc) {
		       if (rc == -EAGAIN)
				goto nomore;
		       else {
				iscsi_conn_failure(conn, rc);
				return 0;
		       }
		}

		/*
		 * Verify and process incoming PDU header.
		 */
		rc = iscsi_tcp_hdr_recv(conn);
		if (!rc && tcp_conn->in.datalen) {
			if (conn->datadgst_en) {
				BUG_ON(!tcp_conn->data_rx_tfm);
				crypto_digest_init(tcp_conn->data_rx_tfm);
			}
			tcp_conn->in_progress = IN_PROGRESS_DATA_RECV;
		} else if (rc) {
			iscsi_conn_failure(conn, rc);
			return 0;
		}
	}

	if (unlikely(conn->suspend_rx))
		goto nomore;

	if (tcp_conn->in_progress == IN_PROGRESS_DDIGEST_RECV) {
		uint32_t recv_digest;

		dprintk("extra data_recv offset %d copy %d\n",
			  tcp_conn->in.offset, tcp_conn->in.copy);
		skb_copy_bits(tcp_conn->in.skb, tcp_conn->in.offset,
				&recv_digest, 4);
		tcp_conn->in.offset += 4;
		tcp_conn->in.copy -= 4;
		if (recv_digest != tcp_conn->in.datadgst) {
			dprintk("iscsi_tcp: data digest error!"
				  "0x%x != 0x%x\n", recv_digest,
				  tcp_conn->in.datadgst);
			iscsi_conn_failure(conn, ISCSI_ERR_DATA_DGST);
			return 0;
		} else {
			dprintk("iscsi_tcp: data digest match!"
				  "0x%x == 0x%x\n", recv_digest,
				  tcp_conn->in.datadgst);
			tcp_conn->in_progress = IN_PROGRESS_WAIT_HEADER;
		}
	}

	if (tcp_conn->in_progress == IN_PROGRESS_DATA_RECV &&
	   tcp_conn->in.copy) {

		dprintk("data_recv offset %d copy %d\n",
		       tcp_conn->in.offset, tcp_conn->in.copy);

		rc = iscsi_data_recv(conn);
		if (rc) {
			if (rc == -EAGAIN)
				goto again;
			iscsi_conn_failure(conn, rc);
			return 0;
		}
		tcp_conn->in.copy -= tcp_conn->in.padding;
		tcp_conn->in.offset += tcp_conn->in.padding;
		if (conn->datadgst_en) {
			if (tcp_conn->in.padding) {
				dprintk("padding -> %d\n",
					  tcp_conn->in.padding);
				memset(pad, 0, tcp_conn->in.padding);
				sg_init_one(&sg, pad, tcp_conn->in.padding);
				crypto_digest_update(tcp_conn->data_rx_tfm,
						     &sg, 1);
			}
			crypto_digest_final(tcp_conn->data_rx_tfm,
					    (u8 *) & tcp_conn->in.datadgst);
			dprintk("rx digest 0x%x\n", tcp_conn->in.datadgst);
			tcp_conn->in_progress = IN_PROGRESS_DDIGEST_RECV;
		} else
			tcp_conn->in_progress = IN_PROGRESS_WAIT_HEADER;
	}

	dprintk("f, processed %d from out of %d padding %d\n",
	       tcp_conn->in.offset - offset, (int)len, tcp_conn->in.padding);
	BUG_ON(tcp_conn->in.offset - offset > len);

	if (tcp_conn->in_progress == IN_PROGRESS_WAIT_HEADER)
		if (tcp_conn->in.ctask) {
			struct iscsi_cls_session *cls_session =
				session_to_cls(conn->session);
			struct istgt_session *istgt_session =
				cls_session->dd_data;

			istgt_ctask_recvlist_add(tcp_conn->in.ctask);
			tcp_conn->in.ctask = NULL;
			schedule_work(&istgt_session->recvwork);
		}

	if (tcp_conn->in.offset - offset != len) {
		dprintk("continue to process %d bytes\n",
		       (int)len - (tcp_conn->in.offset - offset));
		goto more;
	}

nomore:
	processed = tcp_conn->in.offset - offset;
	BUG_ON(processed == 0);
	return processed;

again:
	processed = tcp_conn->in.offset - offset;
	dprintk("c, processed %d from out of %d rd_desc_cnt %d\n",
	          processed, (int)len, (int)rd_desc->count);
	BUG_ON(processed == 0);
	BUG_ON(processed > len);

	conn->rxdata_octets += processed;
	return processed;
}

static void
istgt_tcp_data_ready(struct sock *sk, int flag)
{
	struct iscsi_conn *conn = sk->sk_user_data;
	read_descriptor_t rd_desc;

	read_lock(&sk->sk_callback_lock);

	/* use rd_desc to pass 'conn' to iscsi_tcp_data_recv */
	rd_desc.arg.data = conn;
	rd_desc.count = 1;
	tcp_read_sock(sk, &rd_desc, iscsi_tcp_data_recv);

	read_unlock(&sk->sk_callback_lock);
}

static int
istgt_tcp_conn_bind(struct iscsi_cls_session *cls_session,
		    struct iscsi_cls_conn *cls_conn, uint64_t transport_eph,
		    int is_leading)
{
	struct socket *sock;
	int err;

	sock = sockfd_lookup((int)transport_eph, &err);
	if (!sock) {
		printk(KERN_ERR "iscsi_tcp: sockfd_lookup failed %d\n", err);
		return -EEXIST;
	}

	err = iscsi_tcp_conn_bind(cls_session, cls_conn, transport_eph, is_leading);
	if (err)
		goto out;

	write_lock_bh(&sock->sk->sk_callback_lock);

	sk->sk_data_ready = istgt_tcp_data_ready;

	write_unlock_bh(&sock->sk->sk_callback_lock);
out:
	sock_release(sock);
	return err;
}

static struct iscsi_cls_session *
istgt_tcp_session_create(struct iscsi_transport *iscsit,
			 struct scsi_transport_template *scsit,
			 uint32_t initial_cmdsn, uint32_t *hostno)
{
	struct Scsi_Host *shost;
	struct iscsi_cls_session *cls_session;
	struct iscsi_session *session;
	struct istgt_session *istgt_session;
	int i, err;

	cls_session = iscsi_tcp_session_create(iscsit, scsit, initial_cmdsn,
					       hostno);
	if (!cls_session)
		return NULL;
	shost = iscsi_session_to_shost(cls_session);
	err = scsi_tgt_alloc_queue(shost);
	if (err)
		goto session_free;

	session = class_to_transport_session(cls_session);
	for (i = 0; i < initial_cmdsn; i++) {
		struct iscsi_cmd_task *ctask = session->cmds[i];
		INIT_LIST_HEAD(&ctask_to_ttask(ctask)->hash);
		INIT_LIST_HEAD(&ctask_to_ttask(ctask)->tlist);
	}

	istgt_session =	(struct istgt_session *) cls_session->dd_data;

	INIT_LIST_HEAD(&istgt_session->recvlist);
	INIT_LIST_HEAD(&istgt_session->cmd_hash);
	spin_lock_init(&istgt_session->slock);

	INIT_WORK(&istgt_session->recvwork, istgt_recvworker, cls_session);

	return cls_session;
session_free:
	iscsi_session_teardown(cls_session);
	return NULL;
}

static int istgt_transfer_response(struct scsi_cmnd *scmd,
				   void (*done)(struct scsi_cmnd *))
{
	struct iscsi_cmd_task *ctask = (struct iscsi_cmd_task *) scmd->SCp.ptr;
	struct iscsi_conn *conn = ctask->conn;
	struct iscsi_cls_session *cls_session = session_to_cls(conn->session);
	struct Scsi_Host *shost = iscsi_session_to_shost(cls_session);

	__kfifo_put(conn->xmitqueue, (void*)&ctask, sizeof(void*));
	scsi_queue_work(shost, &conn->xmitwork);

	return 0;
}

static int istgt_transfer_data(struct scsi_cmnd *scmd,
				  void (*done)(struct scsi_cmnd *))
{
	struct iscsi_cmd_task *ctask = (struct iscsi_cmd_task *) scmd->SCp.ptr;

	if (scmd->sc_data_direction == DMA_TO_DEVICE) {
		struct iscsi_tcp_conn *tcp_conn = ctask->conn->dd_data;
		struct sock *sk = tcp_conn->sock->sk;

		/* FIXME: too hacky */
		bh_lock_sock(sk);

		if (tcp_conn->in.ctask == ctask) {
			clear_bit(ISCSI_SUSPEND_BIT, &ctask->conn->suspend_rx);
			sk->sk_data_ready(sk, 0);
		}

		bh_unlock_sock(sk);
	}
	done(scmd);

	return 0;
}

static int istgt_tcp_eh_abort_handler(struct scsi_cmnd *scmd)
{
	BUG();
	return 0;
}

#define	DEFAULT_NR_QUEUED_CMNDS	32
#define TGT_NAME "istgt_tcp"

static struct scsi_host_template istgt_tcp_sht = {
	.name			= TGT_NAME,
	.module			= THIS_MODULE,
	.can_queue		= DEFAULT_NR_QUEUED_CMNDS,
	.sg_tablesize		= SG_ALL,
	.max_sectors		= 65535,
	.use_clustering		= DISABLE_CLUSTERING,
	.transfer_response	= istgt_transfer_response,
	.transfer_data		= istgt_transfer_data,
	.eh_abort_handler	= istgt_tcp_eh_abort_handler,
};

static struct iscsi_transport istgt_tcp_transport = {
	.owner			= THIS_MODULE,
	.name			= TGT_NAME,
	.host_template		= &istgt_tcp_sht,
	.conndata_size		= sizeof(struct iscsi_conn),
	.sessiondata_size	= sizeof(struct istgt_session),
	.max_conn		= 1,
	.max_cmd_len		= ISCSI_TCP_MAX_CMD_LEN,
	.create_session		= istgt_tcp_session_create,
	.destroy_session	= iscsi_tcp_session_destroy,
	.create_conn		= iscsi_tcp_conn_create,
	.destroy_conn		= iscsi_tcp_conn_destroy,
	.bind_conn		= istgt_tcp_conn_bind,
	.start_conn		= iscsi_conn_start,
	.terminate_conn		= iscsi_tcp_terminate_conn,
	.xmit_cmd_task		= istgt_tcp_ctask_xmit,
};

static int __init istgt_tcp_init(void)
{
	printk("iSCSI Target over TCP\n");

	taskcache = kmem_cache_create("istgt_taskcache",
				      sizeof(struct iscsi_data_task), 0,
				      SLAB_HWCACHE_ALIGN, NULL, NULL);
	if (!taskcache)
		return -ENOMEM;

	if (!iscsi_register_transport(&istgt_tcp_transport))
		goto free_taskcache;
	return 0;
free_taskcache:
	kmem_cache_destroy(taskcache);
	return -ENOMEM;
}

static void __exit istgt_tcp_exit(void)
{
	iscsi_unregister_transport(&istgt_tcp_transport);
	kmem_cache_destroy(taskcache);
}

module_init(istgt_tcp_init);
module_exit(istgt_tcp_exit);

MODULE_DESCRIPTION("iSCSI target over TCP");
MODULE_LICENSE("GPL");
