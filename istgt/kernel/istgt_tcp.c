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
#include <scsi/scsi_transport_iscsi.h>
#include <scsi/scsi_tgt.h>
#include <scsi/scsi_tcq.h>

/* tmp - will replace with SCSI logging stuff */
#define eprintk(fmt, args...)					\
do {								\
	printk("%s(%d) " fmt, __FUNCTION__, __LINE__, ##args);	\
} while (0)

#define dprintk eprintk

struct istgt_session {
	struct list_head pending_list;
};

static kmem_cache_t *taskcache;

static void build_r2t(struct iscsi_cmd_task *ctask)
{
	struct iscsi_r2t_rsp *hdr;
	struct iscsi_data_task *dtask;
	struct iscsi_r2t_info *r2t;
	struct iscsi_session *session = ctask->conn->session;
	struct iscsi_tcp_cmd_task *tcp_ctask = ctask->dd_data;
	struct iscsi_tcp_conn *tcp_conn = ctask->conn->dd_data;
	int rc;

/* 	length = req->r2t_length; */
/* 	burst = req->conn->session->param.max_burst_length; */
/* 	offset = be32_to_cpu(cmd_hdr(req)->data_length) - length; */
more:
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
	struct iscsi_cls_session *cls_session;
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

static void istgt_ctask_add(struct iscsi_cmd_task *ctask)
{
	struct iscsi_session *session = ctask->conn->session;
	struct iscsi_cls_session *cls_session;
	struct istgt_session *sess;
	struct iscsi_cmd *hdr = ctask->hdr;
	struct list_head *entry;
	uint32_t cmdsn;

	sess = (struct istgt_session *) cls_session->dd_data;

	if (hdr->opcode & ISCSI_OP_IMMEDIATE) {
		istgt_cmd_exec(ctask);
		return;
	}

	cmdsn = hdr->cmdsn;
	if (cmdsn == session->exp_cmdsn) {
		session->exp_cmdsn = ++cmdsn;
		istgt_cmd_exec(ctask);

		if (list_empty(&sess->pending_list))
			return;
		ctask = list_entry(sess->pending_list.next,
				   struct iscsi_cmd_task, running);
		if (ctask->hdr->cmdsn != cmdsn)
			return;
		list_del_init(&ctask->running);
	} else {
/* 		set_cmd_pending(cmnd); */
		if (before(cmdsn, session->exp_cmdsn)) /* close the conn */
			eprintk("unexpected cmd_sn (%u,%u)\n", cmdsn, session->exp_cmdsn);

/* 		if (after(cmdsn, session->exp_cmdsn + session->max_queued_cmnds)) */
/* 			eprintk("too large cmd_sn (%u,%u)\n", cmd_sn, session->exp_cmd_sn); */

		list_for_each(entry, &sess->pending_list) {
			struct iscsi_cmd_task *tmp;
			tmp = list_entry(entry, struct iscsi_cmd_task, running);
			if (before(cmdsn, tmp->hdr->cmdsn))
				break;
		}

		BUG_ON(!list_empty(&ctask->running));

		list_add_tail(&ctask->running, entry);
	}
}


/*
 * the followings are taken from iscsi_tcp.
 */

int iscsi_tcp_hdr_recv(struct iscsi_conn *conn)
{
	int rc = 0, opcode, ahslen;
	struct iscsi_hdr *hdr;
	struct iscsi_session *session = conn->session;
	struct iscsi_tcp_conn *tcp_conn = conn->dd_data;
	uint32_t cdgst, rdgst = 0;
	struct iscsi_cmd_task *ctask = NULL;

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

	__kfifo_get(session->cmdpool.queue, (void*)&ctask, sizeof(void*));
	ctask->conn = conn;
	INIT_LIST_HEAD(&ctask->running);
	memcpy(ctask->hdr, hdr, sizeof(*hdr));

	opcode = hdr->opcode & ISCSI_OPCODE_MASK;

	dprintk("opcode 0x%x offset %d copy %d ahslen %d datalen %d\n",
		opcode, tcp_conn->in.offset, tcp_conn->in.copy,
		ahslen, tcp_conn->in.datalen);

	switch(opcode) {
	case ISCSI_OP_NOOP_OUT:
		/* TODO */
		BUG();
		break;
	case ISCSI_OP_SCSI_CMD:
/* 		if (!(err = cmnd_insert_hash(cmnd))) */
/* 			scsi_cmnd_start(conn, cmnd); */
		break;
	case ISCSI_OP_SCSI_TMFUNC:
		/* TODO */
		BUG();
		break;
	case ISCSI_OP_SCSI_DATA_OUT:
/* 		data_out_start(conn, cmnd); */
		break;
	case ISCSI_OP_LOGOUT:
/* 		err = cmnd_insert_hash(cmnd); */
		break;
	case ISCSI_OP_TEXT:
	case ISCSI_OP_SNACK:
		rc = -ISCSI_REASON_CMD_NOT_SUPPORTED;
		break;
	default:
		rc = -ISCSI_REASON_CMD_NOT_SUPPORTED;
		break;
	}

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
		break;
	case ISCSI_OP_SCSI_DATA_OUT:
		/* READ DATAT */
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

static inline int
iscsi_hdr_extract(struct iscsi_tcp_conn *tcp_conn)
{
	struct sk_buff *skb = tcp_conn->in.skb;

	tcp_conn->in.zero_copy_hdr = 0;

	if (tcp_conn->in.copy >= tcp_conn->hdr_size &&
	    tcp_conn->in_progress == IN_PROGRESS_WAIT_HEADER) {
		/*
		 * Zero-copy PDU Header: using connection context
		 * to store header pointer.
		 */
		if (skb_shinfo(skb)->frag_list == NULL &&
		    !skb_shinfo(skb)->nr_frags) {
			tcp_conn->in.hdr = (struct iscsi_hdr *)
				((char*)skb->data + tcp_conn->in.offset);
			tcp_conn->in.zero_copy_hdr = 1;
		} else {
			/* ignoring return code since we checked
			 * in.copy before */
			skb_copy_bits(skb, tcp_conn->in.offset,
				&tcp_conn->hdr, tcp_conn->hdr_size);
			tcp_conn->in.hdr = &tcp_conn->hdr;
		}
		tcp_conn->in.offset += tcp_conn->hdr_size;
		tcp_conn->in.copy -= tcp_conn->hdr_size;
	} else {
		int hdr_remains;
		int copylen;

		/*
		 * PDU header scattered across SKB's,
		 * copying it... This'll happen quite rarely.
		 */

		if (tcp_conn->in_progress == IN_PROGRESS_WAIT_HEADER)
			tcp_conn->in.hdr_offset = 0;

		hdr_remains = tcp_conn->hdr_size - tcp_conn->in.hdr_offset;
		BUG_ON(hdr_remains <= 0);

		copylen = min(tcp_conn->in.copy, hdr_remains);
		skb_copy_bits(skb, tcp_conn->in.offset,
			(char*)&tcp_conn->hdr + tcp_conn->in.hdr_offset,
			copylen);

		dprintk("PDU gather offset %d bytes %d in.offset %d "
			"in.copy %d\n", tcp_conn->in.hdr_offset, copylen,
			tcp_conn->in.offset, tcp_conn->in.copy);

		tcp_conn->in.offset += copylen;
		tcp_conn->in.copy -= copylen;
		if (copylen < hdr_remains)  {
			tcp_conn->in_progress = IN_PROGRESS_HEADER_GATHER;
			tcp_conn->in.hdr_offset += copylen;
		        return -EAGAIN;
		}
		tcp_conn->in.hdr = &tcp_conn->hdr;
		tcp_conn->discontiguous_hdr_cnt++;
	        tcp_conn->in_progress = IN_PROGRESS_WAIT_HEADER;
	}

	return 0;
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
		;

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
iscsi_tcp_data_ready(struct sock *sk, int flag)
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

static void
iscsi_tcp_state_change(struct sock *sk)
{
	struct iscsi_tcp_conn *tcp_conn;
	struct iscsi_conn *conn;
	struct iscsi_session *session;
	void (*old_state_change)(struct sock *);

	read_lock(&sk->sk_callback_lock);

	conn = (struct iscsi_conn*)sk->sk_user_data;
	session = conn->session;

	if ((sk->sk_state == TCP_CLOSE_WAIT ||
	     sk->sk_state == TCP_CLOSE) &&
	    !atomic_read(&sk->sk_rmem_alloc)) {
		dprintk("iscsi_tcp_state_change: TCP_CLOSE|TCP_CLOSE_WAIT\n");
		iscsi_conn_failure(conn, ISCSI_ERR_CONN_FAILED);
	}

	tcp_conn = conn->dd_data;
	old_state_change = tcp_conn->old_state_change;

	read_unlock(&sk->sk_callback_lock);

	old_state_change(sk);
}

static void
iscsi_write_space(struct sock *sk)
{
	struct iscsi_conn *conn = (struct iscsi_conn*)sk->sk_user_data;
	struct iscsi_tcp_conn *tcp_conn = conn->dd_data;

	tcp_conn->old_write_space(sk);
	clear_bit(ISCSI_SUSPEND_BIT, &conn->suspend_tx);
	scsi_queue_work(conn->session->host, &conn->xmitwork);
}

static void
iscsi_conn_set_callbacks(struct iscsi_conn *conn)
{
	struct iscsi_tcp_conn *tcp_conn = conn->dd_data;
	struct sock *sk = tcp_conn->sock->sk;

	/* assign new callbacks */
	write_lock_bh(&sk->sk_callback_lock);
	sk->sk_user_data = conn;
	tcp_conn->old_data_ready = sk->sk_data_ready;
	tcp_conn->old_state_change = sk->sk_state_change;
	tcp_conn->old_write_space = sk->sk_write_space;
	sk->sk_data_ready = iscsi_tcp_data_ready;
	sk->sk_state_change = iscsi_tcp_state_change;
	sk->sk_write_space = iscsi_write_space;
	write_unlock_bh(&sk->sk_callback_lock);
}

static void
iscsi_conn_restore_callbacks(struct iscsi_conn *conn)
{
	struct iscsi_tcp_conn *tcp_conn = conn->dd_data;
	struct sock *sk = tcp_conn->sock->sk;

	/* restore socket callbacks, see also: iscsi_conn_set_callbacks() */
	write_lock_bh(&sk->sk_callback_lock);
	sk->sk_user_data    = NULL;
	sk->sk_data_ready   = tcp_conn->old_data_ready;
	sk->sk_state_change = tcp_conn->old_state_change;
	sk->sk_write_space  = tcp_conn->old_write_space;
	sk->sk_no_check	 = 0;
	write_unlock_bh(&sk->sk_callback_lock);
}

static void
iscsi_tcp_terminate_conn(struct iscsi_conn *conn)
{
	struct iscsi_tcp_conn *tcp_conn = conn->dd_data;

	if (!tcp_conn->sock)
		return;

	sock_hold(tcp_conn->sock->sk);
	iscsi_conn_restore_callbacks(conn);
	sock_put(tcp_conn->sock->sk);

	sock_release(tcp_conn->sock);
	tcp_conn->sock = NULL;
	conn->recv_lock = NULL;
}

static int
iscsi_r2tpool_alloc(struct iscsi_session *session)
{
	int i;
	int cmd_i;

	/*
	 * initialize per-task: R2T pool and xmit queue
	 */
	for (cmd_i = 0; cmd_i < session->cmds_max; cmd_i++) {
	        struct iscsi_cmd_task *ctask = session->cmds[cmd_i];
		struct iscsi_tcp_cmd_task *tcp_ctask = ctask->dd_data;

		/*
		 * pre-allocated x4 as much r2ts to handle race when
		 * target acks DataOut faster than we data_xmit() queues
		 * could replenish r2tqueue.
		 */

		/* R2T pool */
		if (iscsi_pool_init(&tcp_ctask->r2tpool, session->max_r2t * 4,
				    (void***)&tcp_ctask->r2ts,
				    sizeof(struct iscsi_r2t_info))) {
			goto r2t_alloc_fail;
		}

		/* R2T xmit queue */
		tcp_ctask->r2tqueue = kfifo_alloc(
		      session->max_r2t * 4 * sizeof(void*), GFP_KERNEL, NULL);
		if (tcp_ctask->r2tqueue == ERR_PTR(-ENOMEM)) {
			iscsi_pool_free(&tcp_ctask->r2tpool,
					(void**)tcp_ctask->r2ts);
			goto r2t_alloc_fail;
		}

		/*
		 * number of
		 * Data-Out PDU's within R2T-sequence can be quite big;
		 * using mempool
		 */
		tcp_ctask->datapool = mempool_create(ISCSI_DTASK_DEFAULT_MAX,
						     mempool_alloc_slab,
						     mempool_free_slab,
						     taskcache);
		if (tcp_ctask->datapool == NULL) {
			kfifo_free(tcp_ctask->r2tqueue);
			iscsi_pool_free(&tcp_ctask->r2tpool,
					(void**)tcp_ctask->r2ts);
			goto r2t_alloc_fail;
		}
		INIT_LIST_HEAD(&tcp_ctask->dataqueue);
	}

	return 0;

r2t_alloc_fail:
	for (i = 0; i < cmd_i; i++) {
		struct iscsi_cmd_task *ctask = session->cmds[i];
		struct iscsi_tcp_cmd_task *tcp_ctask = ctask->dd_data;

		mempool_destroy(tcp_ctask->datapool);
		kfifo_free(tcp_ctask->r2tqueue);
		iscsi_pool_free(&tcp_ctask->r2tpool,
				(void**)tcp_ctask->r2ts);
	}
	return -ENOMEM;
}

static void
iscsi_r2tpool_free(struct iscsi_session *session)
{
	int i;

	for (i = 0; i < session->cmds_max; i++) {
		struct iscsi_cmd_task *ctask = session->cmds[i];
		struct iscsi_tcp_cmd_task *tcp_ctask = ctask->dd_data;

		mempool_destroy(tcp_ctask->datapool);
		kfifo_free(tcp_ctask->r2tqueue);
		iscsi_pool_free(&tcp_ctask->r2tpool,
				(void**)tcp_ctask->r2ts);
	}
}

static struct iscsi_cls_session *
istgt_tcp_session_create(struct iscsi_transport *iscsit,
			 struct scsi_transport_template *scsit,
			 uint32_t initial_cmdsn, uint32_t *hostno)
{
	struct Scsi_Host *shost;
	struct iscsi_cls_session *cls_session;
	struct iscsi_session *session;
	uint32_t hn;
	int err, i;

	cls_session = iscsi_session_setup(iscsit, scsit,
					 sizeof(struct iscsi_tcp_cmd_task),
					 sizeof(struct iscsi_tcp_mgmt_task),
					 initial_cmdsn, &hn);
	if (!cls_session)
		return NULL;
	shost = iscsi_session_to_shost(cls_session);
	err = scsi_tgt_alloc_queue(shost);
	if (err)
		goto session_free;
	*hostno = hn;

	session = class_to_transport_session(cls_session);
	for (i = 0; i < initial_cmdsn; i++) {
		struct iscsi_cmd_task *ctask = session->cmds[i];
		struct iscsi_tcp_cmd_task *tcp_ctask = ctask->dd_data;

		ctask->hdr = &tcp_ctask->hdr;
	}

	for (i = 0; i < session->mgmtpool_max; i++) {
		struct iscsi_mgmt_task *mtask = session->mgmt_cmds[i];
		struct iscsi_tcp_mgmt_task *tcp_mtask = mtask->dd_data;

		mtask->hdr = &tcp_mtask->hdr;
	}

	if (iscsi_r2tpool_alloc(class_to_transport_session(cls_session)))
		goto session_free;

	return cls_session;
session_free:
	iscsi_session_teardown(cls_session);
	return NULL;
}

static void iscsi_tcp_session_destroy(struct iscsi_cls_session *cls_session)
{
	struct iscsi_session *session = class_to_transport_session(cls_session);
	struct iscsi_data_task *dtask, *n;
	int cmd_i;

	for (cmd_i = 0; cmd_i < session->cmds_max; cmd_i++) {
		struct iscsi_cmd_task *ctask = session->cmds[cmd_i];
		struct iscsi_tcp_cmd_task *tcp_ctask = ctask->dd_data;

		list_for_each_entry_safe(dtask, n, &tcp_ctask->dataqueue,
					 item) {
			list_del(&dtask->item);
			mempool_free(dtask, tcp_ctask->datapool);
		}
	}

	iscsi_r2tpool_free(class_to_transport_session(cls_session));
	iscsi_session_teardown(cls_session);
}

static struct iscsi_cls_conn *
iscsi_tcp_conn_create(struct iscsi_cls_session *cls_session, uint32_t conn_idx)
{
	struct iscsi_conn *conn;
	struct iscsi_cls_conn *cls_conn;
	struct iscsi_tcp_conn *tcp_conn;

	cls_conn = iscsi_conn_setup(cls_session, conn_idx);
	if (!cls_conn)
		return NULL;
	conn = cls_conn->dd_data;
	/*
	 * due to strange issues with iser these are not set
	 * in iscsi_conn_setup
	 */
	conn->max_recv_dlength = DEFAULT_MAX_RECV_DATA_SEGMENT_LENGTH;

	tcp_conn = kzalloc(sizeof(*tcp_conn), GFP_KERNEL);
	if (!tcp_conn)
		goto tcp_conn_alloc_fail;

	conn->dd_data = tcp_conn;
	tcp_conn->iscsi_conn = conn;
	tcp_conn->in_progress = IN_PROGRESS_WAIT_HEADER;
	/* initial operational parameters */
	tcp_conn->hdr_size = sizeof(struct iscsi_hdr);
	tcp_conn->data_size = DEFAULT_MAX_RECV_DATA_SEGMENT_LENGTH;

	/* allocate initial PDU receive place holder */
	if (tcp_conn->data_size <= PAGE_SIZE)
		tcp_conn->data = kmalloc(tcp_conn->data_size, GFP_KERNEL);
	else
		tcp_conn->data = (void*)__get_free_pages(GFP_KERNEL,
					get_order(tcp_conn->data_size));
	if (!tcp_conn->data)
		goto max_recv_dlenght_alloc_fail;

	return cls_conn;

max_recv_dlenght_alloc_fail:
	kfree(tcp_conn);
tcp_conn_alloc_fail:
	iscsi_conn_teardown(cls_conn);
	return NULL;
}

static void
iscsi_tcp_conn_destroy(struct iscsi_cls_conn *cls_conn)
{
	struct iscsi_conn *conn = cls_conn->dd_data;
	struct iscsi_tcp_conn *tcp_conn = conn->dd_data;
	int digest = 0;

	if (conn->hdrdgst_en || conn->datadgst_en)
		digest = 1;

	iscsi_conn_teardown(cls_conn);

	/* now free tcp_conn */
	if (digest) {
		if (tcp_conn->tx_tfm)
			crypto_free_tfm(tcp_conn->tx_tfm);
		if (tcp_conn->rx_tfm)
			crypto_free_tfm(tcp_conn->rx_tfm);
		if (tcp_conn->data_tx_tfm)
			crypto_free_tfm(tcp_conn->data_tx_tfm);
		if (tcp_conn->data_rx_tfm)
			crypto_free_tfm(tcp_conn->data_rx_tfm);
	}

	/* free conn->data, size = MaxRecvDataSegmentLength */
	if (tcp_conn->data_size <= PAGE_SIZE)
		kfree(tcp_conn->data);
	else
		free_pages((unsigned long)tcp_conn->data,
			   get_order(tcp_conn->data_size));
	kfree(tcp_conn);
}

static int
iscsi_tcp_conn_bind(struct iscsi_cls_session *cls_session,
		    struct iscsi_cls_conn *cls_conn, uint64_t transport_eph,
		    int is_leading)
{
	struct iscsi_conn *conn = cls_conn->dd_data;
	struct iscsi_tcp_conn *tcp_conn = conn->dd_data;
	struct sock *sk;
	struct socket *sock;
	int err;

	/* lookup for existing socket */
	sock = sockfd_lookup((int)transport_eph, &err);
	if (!sock) {
		printk(KERN_ERR "iscsi_tcp: sockfd_lookup failed %d\n", err);
		return -EEXIST;
	}

	err = iscsi_conn_bind(cls_session, cls_conn, is_leading);
	if (err)
		return err;

	if (conn->stop_stage != STOP_CONN_SUSPEND) {
		/* bind iSCSI connection and socket */
		tcp_conn->sock = sock;

		/* setup Socket parameters */
		sk = sock->sk;
		sk->sk_reuse = 1;
		sk->sk_sndtimeo = 15 * HZ; /* FIXME: make it configurable */
		sk->sk_allocation = GFP_ATOMIC;

		/* FIXME: disable Nagle's algorithm */

		/*
		 * Intercept TCP callbacks for sendfile like receive
		 * processing.
		 */
		conn->recv_lock = &sk->sk_callback_lock;
		iscsi_conn_set_callbacks(conn);
		tcp_conn->sendpage = tcp_conn->sock->ops->sendpage;
		/*
		 * set receive state machine into initial state
		 */
		tcp_conn->in_progress = IN_PROGRESS_WAIT_HEADER;
	}

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
/* 	.transfer_response	= scsi_cmnd_done, */
/* 	.transfer_data		= buffer_ready, */
	.eh_abort_handler	= istgt_tcp_eh_abort_handler,
};

static struct iscsi_transport istgt_tcp_transport = {
	.owner			= THIS_MODULE,
	.name			= TGT_NAME,
	.host_template		= &istgt_tcp_sht,
	.conndata_size		= sizeof(struct iscsi_conn),
	.max_conn		= 1,
	.max_cmd_len		= ISCSI_TCP_MAX_CMD_LEN,
	.create_session		= istgt_tcp_session_create,
	.destroy_session	= iscsi_tcp_session_destroy,
	.create_conn		= iscsi_tcp_conn_create,
	.destroy_conn		= iscsi_tcp_conn_destroy,
	.bind_conn		= iscsi_tcp_conn_bind,
	.start_conn		= iscsi_conn_start,
	.terminate_conn		= iscsi_tcp_terminate_conn,
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
