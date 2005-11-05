/*
 * Copyright (C) 2002-2003 Ardis Technolgies <roman@ardistech.com>
 *
 * Released under the terms of the GNU GPL v2.0.
 */

#include <linux/module.h>
#include <linux/hash.h>
#include <net/tcp.h>
#include <scsi/scsi.h>
#include <scsi/scsi_tcq.h>
#include <linux/mempool.h>

#include <iscsi.h>

static kmem_cache_t *istgt_cmd_cache;
static char dummy_data[1024];

static uint32_t cmnd_write_size(struct iscsi_cmnd *cmnd)
{
	struct iscsi_cmd *hdr = cmnd_hdr(cmnd);

	if (hdr->flags & ISCSI_FLAG_CMD_WRITE)
		return be32_to_cpu(hdr->data_length);
	return 0;
}

static uint32_t cmnd_read_size(struct iscsi_cmnd *cmnd)
{
	struct iscsi_cmd *hdr = cmnd_hdr(cmnd);

	if (hdr->flags & ISCSI_FLAG_CMD_READ) {
		if (!(hdr->flags & ISCSI_FLAG_CMD_WRITE))
			return be32_to_cpu(hdr->data_length);
		if (hdr->flags & ISCSI_FLAG_CMD_READ) {
			struct iscsi_rlength_ahdr *ahdr =
				(struct iscsi_rlength_ahdr *)cmnd->pdu.ahs;
			if (ahdr && ahdr->ahstype == ISCSI_AHSTYPE_RLENGTH)
				return be32_to_cpu(ahdr->read_length);
		}
	}
	return 0;
}

/**
 * create a new command.
 *
 * iscsi_cmnd_create - 
 * @conn: ptr to connection (for i/o)
 *
 * @return    ptr to command or NULL
 */

struct iscsi_cmnd *cmnd_alloc(struct iscsi_conn *conn, int req)
{
	struct iscsi_cmnd *cmnd;

	/* TODO: async interface is necessary ? */
	cmnd = kmem_cache_alloc(istgt_cmd_cache, GFP_KERNEL | __GFP_NOFAIL);

	memset(cmnd, 0, sizeof(*cmnd));
	INIT_LIST_HEAD(&cmnd->list);
	INIT_LIST_HEAD(&cmnd->pdu_list);
	INIT_LIST_HEAD(&cmnd->conn_list);
	INIT_LIST_HEAD(&cmnd->hash_list);
	cmnd->conn = conn;
	spin_lock(&conn->list_lock);
	atomic_inc(&conn->nr_cmnds);
	init_completion(&cmnd->event);
	if (req)
		list_add_tail(&cmnd->conn_list, &conn->pdu_list);
	spin_unlock(&conn->list_lock);
	cmnd->sg = NULL;

	if (req) {
		BUG_ON(!conn->session);
		BUG_ON(!conn->session->ts);
	}

	dprintk("%p:%p\n", conn, cmnd);

	return cmnd;
}

/**
 * create a new command used as response.
 *
 * iscsi_cmnd_create_rsp_cmnd - 
 * @cmnd: ptr to request command
 *
 * @return    ptr to response command or NULL
 */

static struct iscsi_cmnd *iscsi_cmnd_create_rsp_cmnd(struct iscsi_cmnd *cmnd, int final)
{
	struct iscsi_cmnd *rsp = cmnd_alloc(cmnd->conn, 0);

	if (final)
		set_cmnd_final(rsp);
	list_add_tail(&rsp->pdu_list, &cmnd->pdu_list);
	rsp->req = cmnd;
	return rsp;
}

static struct iscsi_cmnd *get_rsp_cmnd(struct iscsi_cmnd *req)
{
	return list_entry(req->pdu_list.prev, struct iscsi_cmnd, pdu_list);
}

static void iscsi_cmnds_init_write(struct list_head *send)
{
	struct iscsi_cmnd *cmnd = list_entry(send->next, struct iscsi_cmnd, list);
	struct iscsi_conn *conn = cmnd->conn;
	struct list_head *pos, *next;

	spin_lock(&conn->list_lock);

	list_for_each_safe(pos, next, send) {
		cmnd = list_entry(pos, struct iscsi_cmnd, list);

		dprintk("%p:%x\n", cmnd, cmnd_opcode(cmnd));

		list_del_init(&cmnd->list);
		BUG_ON(conn != cmnd->conn);
		list_add_tail(&cmnd->list, &conn->write_list);
	}

	spin_unlock(&conn->list_lock);

	nthread_wakeup(conn->session->target);
}

static void iscsi_cmnd_init_write(struct iscsi_cmnd *cmnd)
{
	LIST_HEAD(head);

	if (!list_empty(&cmnd->list)) {
		eprintk("%x %x %x %x %lx %lx %u %u %u %u %u %u %u %d %d\n",
			cmnd_itt(cmnd), cmnd_ttt(cmnd), cmnd_opcode(cmnd),
			cmnd_scsicode(cmnd), cmnd->state, cmnd->flags,
			cmnd->r2t_sn, cmnd->r2t_length, cmnd->is_unsolicited_data,
			cmnd->target_task_tag, cmnd->outstanding_r2t,
			cmnd->hdigest, cmnd->ddigest,
			list_empty(&cmnd->pdu_list), list_empty(&cmnd->hash_list));

		BUG_ON(!list_empty(&cmnd->list));
	}
	list_add(&cmnd->list, &head);
	iscsi_cmnds_init_write(&head);
}

static void do_send_data_rsp(struct iscsi_cmnd *cmnd)
{
	struct iscsi_conn *conn = cmnd->conn;
	struct iscsi_cmnd *data_cmnd;
	struct scatterlist *sg = cmnd->tc->sg;
	struct iscsi_cmd *req = cmnd_hdr(cmnd);
	struct iscsi_data_rsp *rsp;
	uint32_t pdusize, expsize, scsisize, size, offset, sn;
	LIST_HEAD(send);

	dprintk("%p\n", cmnd);
	pdusize = conn->session->param.max_xmit_data_length;
	expsize = cmnd_read_size(cmnd);
	BUG_ON(!cmnd->tc);
	size = min(expsize, cmnd->tc->bufflen);
	eprintk("%u %u\n", expsize, cmnd->tc->bufflen);
	offset = 0;
	sn = 0;

	BUG_ON(!sg);

	while (1) {
		data_cmnd = iscsi_cmnd_create_rsp_cmnd(cmnd, size <= pdusize);
		data_cmnd->sg = sg;
		rsp = (struct iscsi_data_rsp *)&data_cmnd->pdu.bhs;

		rsp->opcode = ISCSI_OP_SCSI_DATA_IN;
		rsp->itt = req->itt;
		rsp->ttt = cpu_to_be32(ISCSI_RESERVED_TAG);
		rsp->offset = offset;
		rsp->datasn = cpu_to_be32(sn);

		if (size <= pdusize) {
			data_cmnd->pdu.datasize = size;
			rsp->flags = ISCSI_FLAG_CMD_FINAL |
				     ISCSI_FLAG_DATA_STATUS;

			scsisize = cmnd->tc->bufflen;
			if (scsisize < expsize) {
				rsp->flags |= ISCSI_FLAG_CMD_UNDERFLOW;
				size = expsize - scsisize;
			} else if (scsisize > expsize) {
				rsp->flags |= ISCSI_FLAG_CMD_OVERFLOW;
				size = scsisize - expsize;
			} else
				size = 0;
			rsp->residual_count = cpu_to_be32(size);
			list_add_tail(&data_cmnd->list, &send);

			break;
		}

		data_cmnd->pdu.datasize = pdusize;

		size -= pdusize;
		offset += pdusize;
		sn++;

		list_add_tail(&data_cmnd->list, &send);
	}

	iscsi_cmnds_init_write(&send);
}

static struct iscsi_cmnd *create_scsi_rsp(struct iscsi_cmnd *req)
{
	struct iscsi_cmnd *rsp;
	struct iscsi_cmd *req_hdr = cmnd_hdr(req);
	struct iscsi_cmd_rsp *rsp_hdr;

	rsp = iscsi_cmnd_create_rsp_cmnd(req, 1);

	rsp_hdr = (struct iscsi_cmd_rsp *)&rsp->pdu.bhs;
	rsp_hdr->opcode = ISCSI_OP_SCSI_CMD_RSP;
	rsp_hdr->flags = ISCSI_FLAG_CMD_FINAL;
	rsp_hdr->response = ISCSI_STATUS_CMD_COMPLETED;
	rsp_hdr->cmd_status = SAM_STAT_GOOD;
	rsp_hdr->itt = req_hdr->itt;

	return rsp;
}

void send_scsi_rsp(struct iscsi_cmnd *req)
{
	struct iscsi_cmnd *rsp;
	struct iscsi_cmd_rsp *rsp_hdr;
	uint32_t size;

	rsp = create_scsi_rsp(req);
	rsp_hdr = (struct iscsi_cmd_rsp *) &rsp->pdu.bhs;
	if ((size = cmnd_read_size(req)) != 0) {
		rsp_hdr->flags |= ISCSI_FLAG_CMD_UNDERFLOW;
		rsp_hdr->residual_count = cpu_to_be32(size);
	}

	iscsi_cmnd_init_write(rsp);
}

struct iscsi_sense_data {
	uint16_t length;
	uint8_t  data[0];
} __packed;

static struct iscsi_cmnd *do_create_sense_rsp(struct iscsi_cmnd *req)
{
	struct iscsi_cmnd *rsp;
	struct iscsi_cmd_rsp *rsp_hdr;
	struct iscsi_sense_data *sense;
	struct scsi_tgt_cmd *stc;
	struct scatterlist *sg = &req->sense_sg;

	rsp = iscsi_cmnd_create_rsp_cmnd(req, 1);

	rsp_hdr = (struct iscsi_cmd_rsp *)&rsp->pdu.bhs;
	rsp_hdr->opcode = ISCSI_OP_SCSI_CMD_RSP;
	rsp_hdr->flags = ISCSI_FLAG_CMD_FINAL;
	rsp_hdr->response = ISCSI_STATUS_CMD_COMPLETED;
	rsp_hdr->cmd_status = SAM_STAT_CHECK_CONDITION;
	rsp_hdr->itt = cmnd_hdr(req)->itt;

	stc = tgt_cmd_to_scsi(req->tc);
	sense = (struct iscsi_sense_data *) stc->sense_buff;
	memmove(sense->data, sense, stc->sense_len);
	/*
	 * this looks broken for ppc
	 */
	sense->length = cpu_to_be16(stc->sense_len);

	sg->page = virt_to_page(stc->sense_buff);
	sg->offset = offset_in_page(stc->sense_buff);
	sg->length = stc->sense_len + sizeof(struct iscsi_sense_data);
	rsp->pdu.datasize = sg->length;
	rsp->sg = sg;

	return rsp;
}

static struct iscsi_cmnd *create_sense_rsp(struct iscsi_cmnd *req,
					   uint8_t sense_key, uint8_t asc, uint8_t ascq)
{
	struct scsi_tgt_cmd *stc;
	struct iscsi_cmnd *rsp;
	struct iscsi_cmd_rsp *rsp_hdr;
	struct iscsi_sense_data *sense;
	struct scatterlist *sg = &req->sense_sg;

	rsp = iscsi_cmnd_create_rsp_cmnd(req, 1);

	rsp_hdr = (struct iscsi_cmd_rsp *)&rsp->pdu.bhs;
	rsp_hdr->opcode = ISCSI_OP_SCSI_CMD_RSP;
	rsp_hdr->flags = ISCSI_FLAG_CMD_FINAL;
	rsp_hdr->response = ISCSI_STATUS_CMD_COMPLETED;
	rsp_hdr->cmd_status = SAM_STAT_CHECK_CONDITION;
	rsp_hdr->itt = cmnd_hdr(req)->itt;

	stc = tgt_cmd_to_scsi(req->tc);
	sg->page = virt_to_page(stc->sense_buff);
	sg->offset = offset_in_page(stc->sense_buff);
	sg->length = stc->sense_len;

	sense = (struct iscsi_sense_data *) stc->sense_buff;
	sense->length = cpu_to_be16(14);
	sense->data[0] = 0xf0;
	sense->data[2] = sense_key;
	sense->data[7] = 6;	// Additional sense length
	sense->data[12] = asc;
	sense->data[13] = ascq;

	rsp->pdu.datasize = sizeof(struct iscsi_sense_data) + 14;
	rsp->sg = sg;

	return rsp;
}

/**
 * Free a command.
 * Also frees the additional header.
 *
 * iscsi_cmnd_remove - 
 * @cmnd: ptr to command
 */

void iscsi_cmnd_remove(struct iscsi_cmnd *cmnd)
{
	struct iscsi_conn *conn;

	if (!cmnd)
		return;
	dprintk("%p\n", cmnd);
	conn = cmnd->conn;
	kfree(cmnd->pdu.ahs);

	if (!list_empty(&cmnd->list)) {
		struct iscsi_cmd *req = cmnd_hdr(cmnd);

		eprintk("cmnd %p still on some list?, %x, %x, %x, %x, %x, %x, %x %lx %lx\n",
			cmnd, req->opcode, req->cdb[0], req->flags, req->itt,
			be32_to_cpu(req->data_length),
			req->cmdsn, be32_to_cpu(cmnd->pdu.datasize), cmnd->state, conn->state);

		if (cmnd->req) {
			struct iscsi_cmd *req = cmnd_hdr(cmnd->req);
			eprintk("%p %x %u\n", req, req->opcode, req->cdb[0]);
		}
		dump_stack();
		BUG();
	}
	list_del(&cmnd->list);
	spin_lock(&conn->list_lock);
	atomic_dec(&conn->nr_cmnds);
	list_del(&cmnd->conn_list);
	spin_unlock(&conn->list_lock);

	if (cmnd->tc)
		cmnd->tc->done(cmnd->tc);
	kmem_cache_free(istgt_cmd_cache, cmnd);
}

static void cmnd_skip_pdu(struct iscsi_cmnd *cmnd)
{
/* 	struct iscsi_conn *conn = cmnd->conn; */
/* 	struct tio *tio = cmnd->tio; */
/* 	char *addr; */
/* 	u32 size; */
/* 	int i; */

	BUG_ON(1);

/* 	eprintk("%x %x %x %u\n", cmnd_itt(cmnd), cmnd_opcode(cmnd), */
/* 		cmnd_hdr(cmnd)->cdb[0], cmnd->pdu.datasize); */

/* 	if (!(size = cmnd->pdu.datasize)) */
/* 		return; */

/* 	if (tio) */
/* 		assert(tio->pg_cnt > 0); */
/* 	else */
/* 		tio = cmnd->tio = tio_alloc(1); */

/* 	addr = page_address(tio->pvec[0]); */
/* 	assert(addr); */
/* 	size = (size + 3) & -4; */
/* 	conn->read_size = size; */
/* 	for (i = 0; size > PAGE_CACHE_SIZE; i++, size -= PAGE_CACHE_SIZE) { */
/* 		assert(i < ISCSI_CONN_IOV_MAX); */
/* 		conn->read_iov[i].iov_base = addr; */
/* 		conn->read_iov[i].iov_len = PAGE_CACHE_SIZE; */
/* 	} */
/* 	conn->read_iov[i].iov_base = addr; */
/* 	conn->read_iov[i].iov_len = size; */
/* 	conn->read_msg.msg_iov = conn->read_iov; */
/* 	conn->read_msg.msg_iovlen = ++i; */
}

static void iscsi_cmnd_reject(struct iscsi_cmnd *req, int reason)
{
/* 	struct iscsi_cmnd *rsp; */
/* 	struct iscsi_reject_hdr *rsp_hdr; */
/* 	struct tio *tio; */
/* 	char *addr; */

	BUG_ON(1);

/* 	rsp = iscsi_cmnd_create_rsp_cmnd(req, 1); */
/* 	rsp_hdr = (struct iscsi_reject_hdr *)&rsp->pdu.bhs; */

/* 	rsp_hdr->opcode = ISCSI_OP_REJECT; */
/* 	rsp_hdr->ffffffff = ISCSI_RESERVED_TAG; */
/* 	rsp_hdr->reason = reason; */

/* 	rsp->tio = tio = tio_alloc(1); */
/* 	addr = page_address(tio->pvec[0]); */
/* 	clear_page(addr); */
/* 	memcpy(addr, &req->pdu.bhs, sizeof(struct iscsi_hdr)); */
/* 	tio->size = rsp->pdu.datasize = sizeof(struct iscsi_hdr); */
/* 	cmnd_skip_pdu(req); */

/* 	req->pdu.bhs.opcode = ISCSI_OP_PDU_REJECT; */
}

static void cmnd_set_sn(struct iscsi_cmnd *cmnd, int set_stat_sn)
{
	struct iscsi_conn *conn = cmnd->conn;
	struct iscsi_session *sess = conn->session;

	if (set_stat_sn)
		cmnd->pdu.bhs.statsn = cpu_to_be32(conn->stat_sn++);
	cmnd->pdu.bhs.exp_statsn = cpu_to_be32(sess->exp_cmd_sn);
	cmnd->pdu.bhs.max_statsn = cpu_to_be32(sess->exp_cmd_sn +
						sess->max_queued_cmnds);
}

static void update_stat_sn(struct iscsi_cmnd *cmnd)
{
	struct iscsi_conn *conn = cmnd->conn;
	uint32_t exp_stat_sn;

	cmnd->pdu.bhs.exp_statsn = exp_stat_sn = be32_to_cpu(cmnd->pdu.bhs.exp_statsn);
	dprintk("%x,%x\n", cmnd_opcode(cmnd), exp_stat_sn);
	if ((int32_t) (exp_stat_sn - conn->exp_stat_sn) > 0 &&
	    (int32_t) (exp_stat_sn - conn->stat_sn) <= 0) {
		// free pdu resources
		cmnd->conn->exp_stat_sn = exp_stat_sn;
	}
}

static int check_cmd_sn(struct iscsi_cmnd *cmnd)
{
	struct iscsi_session *session = cmnd->conn->session;
	uint32_t cmd_sn;

	cmnd->pdu.bhs.statsn = cmd_sn = be32_to_cpu(cmnd->pdu.bhs.statsn);
	dprintk("%d(%d)\n", cmd_sn, session->exp_cmd_sn);
	if ((int32_t) (cmd_sn - session->exp_cmd_sn) >= 0)
		return 0;
	eprintk("sequence error (%x,%x)\n", cmd_sn, session->exp_cmd_sn);
	return -ISCSI_PROTOCOL_ERROR;
}

static struct iscsi_cmnd *__cmnd_find_hash(struct iscsi_session *session,
					   uint32_t itt, uint32_t ttt)
{
	struct list_head *head;
	struct iscsi_cmnd *cmnd;

	head = &session->cmnd_hash[cmnd_hashfn(itt)];

	list_for_each_entry(cmnd, head, hash_list) {
		if (cmnd->pdu.bhs.itt == itt) {
			if ((ttt != ISCSI_RESERVED_TAG) && (ttt != cmnd->target_task_tag))
				continue;
			return cmnd;
		}
	}

	return NULL;
}

static struct iscsi_cmnd *cmnd_find_hash(struct iscsi_session *session,
					 uint32_t itt, uint32_t ttt)
{
	struct iscsi_cmnd *cmnd;

	spin_lock(&session->cmnd_hash_lock);

	cmnd = __cmnd_find_hash(session, itt, ttt);

	spin_unlock(&session->cmnd_hash_lock);

	return cmnd;
}

static int cmnd_insert_hash(struct iscsi_cmnd *cmnd)
{
	struct iscsi_session *session = cmnd->conn->session;
	struct iscsi_cmnd *tmp;
	struct list_head *head;
	int err = 0;
	uint32_t itt = cmnd->pdu.bhs.itt;

	dprintk("%p:%x\n", cmnd, itt);
	if (itt == ISCSI_RESERVED_TAG) {
		err = -ISCSI_PROTOCOL_ERROR;
		goto out;
	}

	head = &session->cmnd_hash[cmnd_hashfn(cmnd->pdu.bhs.itt)];

	spin_lock(&session->cmnd_hash_lock);

	tmp = __cmnd_find_hash(session, itt, ISCSI_RESERVED_TAG);
	if (!tmp) {
		list_add_tail(&cmnd->hash_list, head);
		set_cmnd_hashed(cmnd);
	} else
		err = -TASK_IN_PROGRESS;

	spin_unlock(&session->cmnd_hash_lock);

	if (!err) {
		update_stat_sn(cmnd);
		err = check_cmd_sn(cmnd);
	}

out:
	return err;
}

static void __cmnd_remove_hash(struct iscsi_cmnd *cmnd)
{
	list_del(&cmnd->hash_list);
}

static void cmnd_remove_hash(struct iscsi_cmnd *cmnd)
{
	struct iscsi_session *session = cmnd->conn->session;
	struct iscsi_cmnd *tmp;

	spin_lock(&session->cmnd_hash_lock);

	tmp = __cmnd_find_hash(session, cmnd->pdu.bhs.itt, ISCSI_RESERVED_TAG);

	if (tmp && tmp == cmnd)
		__cmnd_remove_hash(tmp);
	else
		eprintk("%p:%x not found\n", cmnd, cmnd_itt(cmnd));

	spin_unlock(&session->cmnd_hash_lock);
}

static void cmnd_skip_data(struct iscsi_cmnd *req)
{
	struct iscsi_cmnd *rsp;
	struct iscsi_cmd_rsp *rsp_hdr;
	uint32_t size;

	rsp = get_rsp_cmnd(req);
	rsp_hdr = (struct iscsi_cmd_rsp *)&rsp->pdu.bhs;
	if (cmnd_opcode(rsp) != ISCSI_OP_SCSI_CMD_RSP) {
		eprintk("unexpected response command %u\n", cmnd_opcode(rsp));
		return;
	}

	size = cmnd_write_size(req);
	if (size) {
		rsp_hdr->flags |= ISCSI_FLAG_CMD_UNDERFLOW;
		rsp_hdr->residual_count = cpu_to_be32(size);
	}
	size = cmnd_read_size(req);
	if (size) {
		if (cmnd_hdr(req)->flags & ISCSI_FLAG_CMD_WRITE) {
			rsp_hdr->flags |= ISCSI_FLAG_CMD_BIDI_UNDERFLOW;
			rsp_hdr->bi_residual_count = cpu_to_be32(size);
		} else {
			rsp_hdr->flags |= ISCSI_FLAG_CMD_BIDI_OVERFLOW;
			rsp_hdr->residual_count = cpu_to_be32(size);
		}
	}
	req->pdu.bhs.opcode =
		(req->pdu.bhs.opcode & ~ISCSI_OPCODE_MASK) | ISCSI_OP_SCSI_REJECT;

	cmnd_skip_pdu(req);
}

static int cmnd_recv_pdu(struct iscsi_conn *conn, struct tgt_cmd *tc,
			 uint32_t offset, uint32_t size)
{
	int idx, i;
	char *addr;
	struct scatterlist *sg;

	dprintk("%u,%u\n", offset, size);

	BUG_ON(!tc);
	BUG_ON(!tc->sg);
	sg = tc->sg;
	offset += sg->offset;

	if (!(offset < sg->offset + tc->bufflen) ||
	    !(offset + size <= sg->offset + tc->bufflen)) {
		eprintk("%u %u %u %u", offset, size, sg->offset, tc->bufflen);
		return -EIO;
	}
	BUG_ON(!(offset < sg->offset + tc->bufflen));
	BUG_ON(!(offset + size <= sg->offset + tc->bufflen));

	idx = offset >> PAGE_CACHE_SHIFT;
	offset &= ~PAGE_CACHE_MASK;

	conn->read_msg.msg_iov = conn->read_iov;
	conn->read_size = (size + 3) & -4;
	conn->read_overflow = 0;

	i = 0;
	while (1) {
		sg = tc->sg + idx;
		BUG_ON(!sg);
		BUG_ON(!sg->page);
		addr = page_address(sg->page);
		BUG_ON(!addr);

		conn->read_iov[i].iov_base =  addr + offset;
		if (offset + size <= PAGE_CACHE_SIZE) {
			conn->read_iov[i].iov_len = size;
			conn->read_msg.msg_iovlen = ++i;
			break;
		}
		conn->read_iov[i].iov_len = PAGE_CACHE_SIZE - offset;
		size -= conn->read_iov[i].iov_len;
		offset = 0;
		if (++i >= ISCSI_CONN_IOV_MAX) {
			conn->read_msg.msg_iovlen = i;
			conn->read_overflow = size;
			conn->read_size -= size;
			break;
		}

		idx++;
	}

	return 0;
}

static void send_r2t(struct iscsi_cmnd *req)
{
	struct iscsi_cmnd *rsp;
	struct iscsi_r2t_rsp *rsp_hdr;
	uint32_t length, offset, burst;
	LIST_HEAD(send);

	length = req->r2t_length;
	burst = req->conn->session->param.max_burst_length;
	offset = be32_to_cpu(cmnd_hdr(req)->data_length) - length;

	do {
		rsp = iscsi_cmnd_create_rsp_cmnd(req, 0);
		rsp->pdu.bhs.ttt = req->target_task_tag;

		rsp_hdr = (struct iscsi_r2t_rsp *)&rsp->pdu.bhs;
		rsp_hdr->opcode = ISCSI_OP_R2T;
		rsp_hdr->flags = ISCSI_FLAG_CMD_FINAL;
		memcpy(rsp_hdr->lun, cmnd_hdr(req)->lun, 8);
		rsp_hdr->itt = cmnd_hdr(req)->itt;
		rsp_hdr->r2tsn = cpu_to_be32(req->r2t_sn++);
		rsp_hdr->data_offset = cpu_to_be32(offset);
		if (length > burst) {
			rsp_hdr->data_length = cpu_to_be32(burst);
			length -= burst;
			offset += burst;
		} else {
			rsp_hdr->data_length = cpu_to_be32(length);
			length = 0;
		}

		dprintk("%x %u %u %u %u\n", cmnd_itt(req),
			be32_to_cpu(rsp_hdr->data_length),
			be32_to_cpu(rsp_hdr->data_offset),
			be32_to_cpu(rsp_hdr->r2tsn), req->outstanding_r2t);

		list_add_tail(&rsp->list, &send);

		if (++req->outstanding_r2t >= req->conn->session->param.max_outstanding_r2t)
			break;

	} while (length);

	iscsi_cmnds_init_write(&send);
}

static void __scsi_cmnd_done(void *data)
{
	struct tgt_cmd *tc = (struct tgt_cmd *) data;
	struct iscsi_cmnd *cmnd = (struct iscsi_cmnd *) tc->private;
	struct iscsi_cmd *req = cmnd_hdr(cmnd);

	if (tc->result != SAM_STAT_GOOD) {
		struct iscsi_cmnd *rsp;

		rsp = do_create_sense_rsp(cmnd);
		iscsi_cmnd_init_write(rsp);
		return;
	}

	switch (req->cdb[0]) {
	case INQUIRY:
	case REPORT_LUNS:
	case READ_CAPACITY:
	case MODE_SENSE:
	case REQUEST_SENSE:
	case SERVICE_ACTION_IN:
	case READ_6:
	case READ_10:
	case READ_16:
		do_send_data_rsp(cmnd);
		break;
	case WRITE_6:
	case WRITE_10:
	case WRITE_16:
	case WRITE_VERIFY:
	case START_STOP:
	case TEST_UNIT_READY:
	case SYNCHRONIZE_CACHE:
	case VERIFY:
	case VERIFY_16:
	case RESERVE:
	case RELEASE:
	case RESERVE_10:
	case RELEASE_10:
		send_scsi_rsp(cmnd);
		break;
	default:
		BUG_ON(1);
		break;
	}
}

/* TODO : merge this with nthread. */
static int scsi_cmnd_done(struct tgt_cmd *tc)
{
	int err;
	struct iscsi_cmnd *cmnd = (struct iscsi_cmnd *) tc->private;

	INIT_WORK(&cmnd->work, __scsi_cmnd_done, tc);
	err = schedule_work(&cmnd->work);
	BUG_ON(!err);

	return TGT_CMD_XMIT_OK;
}

static void tgt_scsi_cmd_create(struct iscsi_cmnd *req)
{
	struct iscsi_cmd *req_hdr = cmnd_hdr(req);
	struct iscsi_conn *conn = req->conn;
	struct tgt_protocol *proto = conn->session->ts->target->proto;
	enum dma_data_direction data_dir;
	int tags = MSG_SIMPLE_TAG;;

	/*
	 * handle bidi later
	 */
	if (req_hdr->flags & ISCSI_FLAG_CMD_WRITE)
		data_dir = DMA_TO_DEVICE;
	else if (req_hdr->flags & ISCSI_FLAG_CMD_READ)
		data_dir = DMA_FROM_DEVICE;
	else
		data_dir = DMA_NONE;

	switch (req->pdu.bhs.flags & ISCSI_FLAG_CMD_ATTR_MASK) {
	case ISCSI_ATTR_UNTAGGED:
	case ISCSI_ATTR_SIMPLE:
		tags = MSG_SIMPLE_TAG;
		break;
	case ISCSI_ATTR_ORDERED:
		tags = MSG_ORDERED_TAG;
		break;
	case ISCSI_ATTR_HEAD_OF_QUEUE:
		tags = MSG_HEAD_TAG;
		break;
	case ISCSI_ATTR_ACA:
		break;
	}

	req->tc = proto->create_cmd(conn->session->ts, req, req_hdr->cdb,
				    be32_to_cpu(req_hdr->data_length),
				    data_dir, req_hdr->lun,
				    sizeof(req_hdr->lun),
				    tags);
	BUG_ON(!req->tc);

	if (data_dir == DMA_TO_DEVICE && be32_to_cpu(req_hdr->data_length)) {
		switch (req_hdr->cdb[0]) {
		case WRITE_6:
		case WRITE_10:
		case WRITE_16:
		case WRITE_VERIFY:
			break;
		default:
			eprintk("%x\n", req_hdr->cdb[0]);
			break;
		}
	}
}

static void scsi_cmnd_exec(struct iscsi_cmnd *cmnd)
{
	struct tgt_cmd *cmd = cmnd->tc;

	if (cmnd->r2t_length) {
		if (!cmnd->is_unsolicited_data)
			send_r2t(cmnd);
	} else {
		set_cmnd_waitio(cmnd);
		if (cmnd->tc)
			cmd->done(cmd);
		else
			tgt_scsi_cmd_create(cmnd);
	}
}

static int noop_out_start(struct iscsi_conn *conn, struct iscsi_cmnd *cmnd)
{
	uint32_t size, tmp;
	int i = 0, err = 0;

	if (cmnd_ttt(cmnd) != cpu_to_be32(ISCSI_RESERVED_TAG)) {
		/*
		 * We don't request a NOP-Out by sending a NOP-In.
		 * See 10.18.2 in the draft 20.
		 */
		eprintk("initiator bug %x\n", cmnd_itt(cmnd));
		err = -ISCSI_PROTOCOL_ERROR;
		goto out;
	}

	if (cmnd_itt(cmnd) == cpu_to_be32(ISCSI_RESERVED_TAG)) {
		if (!(cmnd->pdu.bhs.opcode & ISCSI_OP_IMMEDIATE))
			eprintk("%s\n","initiator bug!");
		update_stat_sn(cmnd);
		err = check_cmd_sn(cmnd);
		goto out;
	} else if ((err = cmnd_insert_hash(cmnd)) < 0) {
		eprintk("ignore this request %x\n", cmnd_itt(cmnd));
		goto out;
	}

	if ((size = cmnd->pdu.datasize)) {
		size = (size + 3) & -4;
		conn->read_msg.msg_iov = conn->read_iov;
		if (cmnd->pdu.bhs.itt != cpu_to_be32(ISCSI_RESERVED_TAG)) {
/* 			struct tio *tio; */
			int pg_cnt = get_pgcnt(size, 0);

			BUG_ON(pg_cnt >= ISCSI_CONN_IOV_MAX);
			BUG_ON(1);
/* 			cmnd->tio = tio = tio_alloc(pg_cnt); */
/* 			tio_set(tio, size, 0); */

/* 			for (i = 0; i < pg_cnt; i++) { */
/* 				conn->read_iov[i].iov_base */
/* 					= page_address(tio->pvec[i]); */
/* 				tmp = min_t(u32, size, PAGE_CACHE_SIZE); */
/* 				conn->read_iov[i].iov_len = tmp; */
/* 				conn->read_size += tmp; */
/* 				size -= tmp; */
/* 			} */
		} else {
			for (i = 0; i < ISCSI_CONN_IOV_MAX; i++) {
				conn->read_iov[i].iov_base = dummy_data;
				tmp = min_t(uint32_t, size, sizeof(dummy_data));
				conn->read_iov[i].iov_len = tmp;
				conn->read_size += tmp;
				size -= tmp;
			}
		}
		BUG_ON(size);
		conn->read_overflow = size;
		conn->read_msg.msg_iovlen = i;
	}

out:
	return err;
}

static uint32_t get_next_ttt(struct iscsi_session *session)
{
	uint32_t ttt;

	if (session->next_ttt == ISCSI_RESERVED_TAG)
		session->next_ttt++;
	ttt = session->next_ttt++;

	return cpu_to_be32(ttt);
}

static void scsi_cmnd_start(struct iscsi_conn *conn, struct iscsi_cmnd *req)
{
	struct iscsi_cmd *req_hdr = cmnd_hdr(req);

	dprintk("scsi command: %02x\n", req_hdr->cdb[0]);

	switch (req_hdr->cdb[0]) {
	case SERVICE_ACTION_IN:
		if ((req_hdr->cdb[1] & 0x1f) != 0x10)
			goto error;

	case INQUIRY:
	case REPORT_LUNS:
	case TEST_UNIT_READY:
	case SYNCHRONIZE_CACHE:
	case VERIFY:
	case VERIFY_16:
	case START_STOP:
	case READ_CAPACITY:
	case MODE_SENSE:
	case REQUEST_SENSE:
	case RESERVE:
	case RELEASE:
	case RESERVE_10:
	case RELEASE_10:
	case READ_6:
	case READ_10:
	case READ_16:
	{
		if (!(req_hdr->flags & ISCSI_FLAG_CMD_FINAL) ||
		      req->pdu.datasize) {
			/* unexpected unsolicited data */
			eprintk("%x %x\n", cmnd_itt(req), req_hdr->cdb[0]);
			create_sense_rsp(req, ABORTED_COMMAND, 0xc, 0xc);
			cmnd_skip_data(req);
		}
		break;
	}
	case WRITE_6:
	case WRITE_10:
	case WRITE_16:
	case WRITE_VERIFY:
	{
		struct iscsi_sess_param *param = &conn->session->param;

		/*
		 * We don't know this command arrives in order,
		 * however we need to allocate buffer for immediate
		 * and unsolicited data. tgt will not start to perform
		 * this command until we call cmd->done so we don't
		 * need to worry about the order of the command.
		 */
		tgt_scsi_cmd_create(req);
		wait_for_completion(&req->event);

		req->r2t_length = be32_to_cpu(req_hdr->data_length) - req->pdu.datasize;
		req->is_unsolicited_data = !(req_hdr->flags &
						ISCSI_FLAG_CMD_FINAL);
		req->target_task_tag = get_next_ttt(conn->session);

		if (!param->immediate_data && req->pdu.datasize)
			eprintk("%x %x\n", cmnd_itt(req), req_hdr->cdb[0]);

		if (param->initial_r2t &&
		    !(req_hdr->flags & ISCSI_FLAG_CMD_FINAL))
			eprintk("%x %x\n", cmnd_itt(req), req_hdr->cdb[0]);

		if (req_hdr->cdb[0] == WRITE_VERIFY && req_hdr->cdb[1] & 0x02)
			eprintk("Verification is ignored %x\n", cmnd_itt(req));

		if (req->pdu.datasize) {
			if (cmnd_recv_pdu(conn, req->tc, 0, req->pdu.datasize) < 0)
				BUG_ON(1);
		}
		break;
	}
	error:
	default:
		eprintk("Unsupported %x\n", req_hdr->cdb[0]);
		create_sense_rsp(req, ILLEGAL_REQUEST, 0x20, 0x0);
		cmnd_skip_data(req);
		break;
	}

	return;
}

static void data_out_start(struct iscsi_conn *conn, struct iscsi_cmnd *cmnd)
{
	struct iscsi_data *req = (struct iscsi_data *)&cmnd->pdu.bhs;
	struct iscsi_cmnd *scsi_cmnd = NULL;
	uint32_t offset = be32_to_cpu(req->offset);

	update_stat_sn(cmnd);

	cmnd->req = scsi_cmnd = cmnd_find_hash(conn->session, req->itt, req->ttt);
	if (!scsi_cmnd) {
		eprintk("unable to find scsi task %x %x\n",
			cmnd_itt(cmnd), cmnd_ttt(cmnd));
		goto skip_data;
	}

	if (scsi_cmnd->r2t_length < cmnd->pdu.datasize) {
		eprintk("invalid data len %x %u %u\n",
			cmnd_itt(scsi_cmnd), cmnd->pdu.datasize, scsi_cmnd->r2t_length);
		goto skip_data;
	}

	if (scsi_cmnd->r2t_length + offset != cmnd_write_size(scsi_cmnd)) {
		eprintk("%x %u %u %u\n", cmnd_itt(scsi_cmnd), scsi_cmnd->r2t_length,
			offset,	cmnd_write_size(scsi_cmnd));
		goto skip_data;
	}

	scsi_cmnd->r2t_length -= cmnd->pdu.datasize;

	if (req->ttt == cpu_to_be32(ISCSI_RESERVED_TAG)) {
		/* unsolicited burst data */
		if (scsi_cmnd->pdu.bhs.flags & ISCSI_FLAG_CMD_FINAL) {
			eprintk("unexpected data from %x %x\n",
				cmnd_itt(cmnd), cmnd_ttt(cmnd));
			goto skip_data;
		}
	}

	dprintk("%u %p %p %u %u\n", req->ttt, cmnd, scsi_cmnd,
		offset, cmnd->pdu.datasize);

	if (cmnd_recv_pdu(conn, scsi_cmnd->tc, offset, cmnd->pdu.datasize) < 0)
		goto skip_data;
	return;

skip_data:
	cmnd->pdu.bhs.opcode = ISCSI_OP_DATA_REJECT;
	cmnd_skip_pdu(cmnd);
	return;
}

static void data_out_end(struct iscsi_conn *conn, struct iscsi_cmnd *cmnd)
{
	struct iscsi_data *req = (struct iscsi_data *) &cmnd->pdu.bhs;
	struct iscsi_cmnd *scsi_cmnd;
	uint32_t offset;

	BUG_ON(!cmnd);
	scsi_cmnd = cmnd->req;
	BUG_ON(!scsi_cmnd);

	if (conn->read_overflow) {
		eprintk("%x %u\n", cmnd_itt(cmnd), conn->read_overflow);
		offset = be32_to_cpu(req->offset);
		offset += cmnd->pdu.datasize - conn->read_overflow;
		if (cmnd_recv_pdu(conn, scsi_cmnd->tc, offset, conn->read_overflow) < 0)
			BUG_ON(1);
		return;
	}

	if (req->ttt == cpu_to_be32(ISCSI_RESERVED_TAG)) {
		if (req->flags & ISCSI_FLAG_CMD_FINAL) {
			scsi_cmnd->is_unsolicited_data = 0;
			if (!cmnd_pending(scsi_cmnd))
				scsi_cmnd_exec(scsi_cmnd);
		}
	} else {
		/* TODO : proper error handling */
		if (!(req->flags & ISCSI_FLAG_CMD_FINAL) &&
		    scsi_cmnd->r2t_length == 0)
			eprintk("initiator error %x\n", cmnd_itt(scsi_cmnd));

		if (!(req->flags & ISCSI_FLAG_CMD_FINAL))
			goto out;

		scsi_cmnd->outstanding_r2t--;

		if (scsi_cmnd->r2t_length == 0)
			BUG_ON(!list_empty(&scsi_cmnd->pdu_list));

		scsi_cmnd_exec(scsi_cmnd);
	}

out:
	iscsi_cmnd_remove(cmnd);
	return;
}

/* static int __cmnd_abort(struct iscsi_cmnd *cmnd) */
/* { */
/* 	if (!cmnd_waitio(cmnd)) { */
/* 		cmnd_release(cmnd, 1); */
/* 		return 0; */
/* 	} else */
/* 		return -ISCSI_RESPONSE_UNKNOWN_TASK; */
/* } */

/* static int cmnd_abort(struct iscsi_session *session, u32 itt) */
/* { */
/* 	struct iscsi_cmnd *cmnd; */
/* 	int err =  -ISCSI_RESPONSE_UNKNOWN_TASK; */

/* 	if ((cmnd = cmnd_find_hash(session, itt, ISCSI_RESERVED_TAG))) { */
/* 		eprintk("%x %x %x %u %u %u %u\n", cmnd_itt(cmnd), cmnd_opcode(cmnd), */
/* 			cmnd->r2t_length, cmnd_scsicode(cmnd), */
/* 			cmnd_write_size(cmnd), cmnd->is_unsolicited_data, */
/* 			cmnd->outstanding_r2t); */
/* 		err = __cmnd_abort(cmnd); */
/* 	} */

/* 	return err; */
/* } */

/* static int target_reset(struct iscsi_cmnd *req, u32 lun, int all) */
/* { */
/* 	struct iscsi_target *target = req->conn->session->target; */
/* 	struct iscsi_session *session; */
/* 	struct iscsi_conn *conn; */
/* 	struct iscsi_cmnd *cmnd, *tmp; */

/* 	list_for_each_entry(session, &target->session_list, list) { */
/* 		list_for_each_entry(conn, &session->conn_list, list) { */
/* 			list_for_each_entry_safe(cmnd, tmp, &conn->pdu_list, conn_list) { */
/* 				if (cmnd == req) */
/* 					continue; */

/* 				if (all) */
/* 					__cmnd_abort(cmnd); */
/* 				else if (translate_lun(cmnd_hdr(cmnd)->lun) == lun) */
/* 					__cmnd_abort(cmnd); */
/* 			} */
/* 		} */
/* 	} */

/* 	return 0; */
/* } */

/* static void task_set_abort(struct iscsi_cmnd *req) */
/* { */
/* 	struct iscsi_session *session = req->conn->session; */
/* 	struct iscsi_conn *conn; */
/* 	struct iscsi_cmnd *cmnd, *tmp; */

/* 	list_for_each_entry(conn, &session->conn_list, list) { */
/* 		list_for_each_entry_safe(cmnd, tmp, &conn->pdu_list, conn_list) { */
/* 			if (cmnd != req) */
/* 				__cmnd_abort(cmnd); */
/* 		} */
/* 	} */
/* } */

static void execute_task_management(struct iscsi_cmnd *req)
{
/* 	struct iscsi_conn *conn = req->conn; */
/* 	struct iscsi_target *target = conn->session->target; */
	struct iscsi_cmnd *rsp;
	struct iscsi_tm *req_hdr = (struct iscsi_tm *)&req->pdu.bhs;
	struct iscsi_tm_rsp *rsp_hdr;
	int function = req_hdr->flags & ISCSI_FLAG_TM_FUNC_MASK;

	rsp = iscsi_cmnd_create_rsp_cmnd(req, 1);
	rsp_hdr = (struct iscsi_tm_rsp *)&rsp->pdu.bhs;

	rsp_hdr->opcode = ISCSI_OP_SCSI_TMFUNC_RSP;
	rsp_hdr->flags = ISCSI_FLAG_CMD_FINAL;
	rsp_hdr->itt = req_hdr->itt;
/* 	rsp_hdr->response = ISCSI_TMF_RSP_COMPLETE; */
	rsp_hdr->response = ISCSI_TMF_RSP_REJECTED;

	eprintk("%x %d %x\n", cmnd_itt(req), function, req_hdr->rtt);

/* 	switch (function) { */
/* 	case ISCSI_FUNCTION_ABORT_TASK: */
/* 	case ISCSI_FUNCTION_ABORT_TASK_SET: */
/* 	case ISCSI_FUNCTION_CLEAR_ACA: */
/* 	case ISCSI_FUNCTION_CLEAR_TASK_SET: */
/* 	case ISCSI_FUNCTION_LOGICAL_UNIT_RESET: */
/* 		lun = translate_lun(req_hdr->lun); */
/* 		if (!volume_lookup(target, lun)) { */
/* 			rsp_hdr->response = ISCSI_RESPONSE_UNKNOWN_LUN; */
/* 			goto out; */
/* 		} */
/* 	} */

/* 	switch (function) { */
/* 	case ISCSI_FUNCTION_ABORT_TASK: */
/* 		if ((err = cmnd_abort(conn->session, req_hdr->rtt)) < 0) */
/* 			rsp_hdr->response = -err; */
/* 		break; */
/* 	case ISCSI_FUNCTION_ABORT_TASK_SET: */
/* 		task_set_abort(req); */
/* 		break; */
/* 	case ISCSI_FUNCTION_CLEAR_ACA: */
/* 		rsp_hdr->response = ISCSI_RESPONSE_FUNCTION_UNSUPPORTED; */
/* 		break; */
/* 	case ISCSI_FUNCTION_CLEAR_TASK_SET: */
/* 		rsp_hdr->response = ISCSI_RESPONSE_FUNCTION_UNSUPPORTED; */
/* 		break; */
/* 	case ISCSI_FUNCTION_LOGICAL_UNIT_RESET: */
/* 		target_reset(req, translate_lun(req_hdr->lun), 0); */
/* 		break; */
/* 	case ISCSI_FUNCTION_TARGET_WARM_RESET: */
/* 	case ISCSI_FUNCTION_TARGET_COLD_RESET: */
/* 		target_reset(req, 0, 1); */
/* 		if (function == ISCSI_FUNCTION_TARGET_COLD_RESET) */
/* 			set_cmnd_close(rsp); */
/* 		break; */
/* 	case ISCSI_FUNCTION_TASK_REASSIGN: */
/* 		rsp_hdr->response = ISCSI_RESPONSE_FUNCTION_UNSUPPORTED; */
/* 		break; */
/* 	default: */
/* 		rsp_hdr->response = ISCSI_RESPONSE_FUNCTION_REJECTED; */
/* 		break; */
/* 	} */
/* out: */
	iscsi_cmnd_init_write(rsp);
}

static void noop_out_exec(struct iscsi_cmnd *req)
{
	struct iscsi_cmnd *rsp;
	struct iscsi_nopin *rsp_hdr;

	if (cmnd_itt(req) != cpu_to_be32(ISCSI_RESERVED_TAG)) {
		rsp = iscsi_cmnd_create_rsp_cmnd(req, 1);

		rsp_hdr = (struct iscsi_nopin *)&rsp->pdu.bhs;
		rsp_hdr->opcode = ISCSI_OP_NOOP_IN;
		rsp_hdr->flags = ISCSI_FLAG_CMD_FINAL;
		rsp_hdr->itt = req->pdu.bhs.itt;
		rsp_hdr->ttt = cpu_to_be32(ISCSI_RESERVED_TAG);

/* 		if (req->pdu.datasize) */
/* 			assert(req->tio); */
/* 		else */
/* 			assert(!req->tio); */

/* 		if (req->tio) { */
/* 			tio_get(req->tio); */
/* 			rsp->tio = req->tio; */
/* 		} */

		BUG_ON(get_pgcnt(req->pdu.datasize, 0) >= ISCSI_CONN_IOV_MAX);
		rsp->pdu.datasize = req->pdu.datasize;
		iscsi_cmnd_init_write(rsp);
	} else
		iscsi_cmnd_remove(req);
}

static void logout_exec(struct iscsi_cmnd *req)
{
	struct iscsi_logout *req_hdr;
	struct iscsi_cmnd *rsp;
	struct iscsi_logout_rsp *rsp_hdr;

	req_hdr = (struct iscsi_logout *)&req->pdu.bhs;
	rsp = iscsi_cmnd_create_rsp_cmnd(req, 1);
	rsp_hdr = (struct iscsi_logout_rsp *)&rsp->pdu.bhs;
	rsp_hdr->opcode = ISCSI_OP_LOGOUT_RSP;
	rsp_hdr->flags = ISCSI_FLAG_CMD_FINAL;
	rsp_hdr->itt = req_hdr->itt;
	set_cmnd_close(rsp);
	iscsi_cmnd_init_write(rsp);
}

static void iscsi_cmnd_exec(struct iscsi_cmnd *cmnd)
{
	dprintk("%p,%x,%u\n", cmnd, cmnd_opcode(cmnd),
		cmnd->pdu.bhs.statsn);

	switch (cmnd_opcode(cmnd)) {
	case ISCSI_OP_NOOP_OUT:
		noop_out_exec(cmnd);
		break;
	case ISCSI_OP_SCSI_CMD:
		scsi_cmnd_exec(cmnd);
		break;
	case ISCSI_OP_SCSI_TMFUNC:
		execute_task_management(cmnd);
		break;
	case ISCSI_OP_LOGOUT:
		logout_exec(cmnd);
		break;
	case ISCSI_OP_SCSI_REJECT:
		iscsi_cmnd_init_write(get_rsp_cmnd(cmnd));
		break;
	case ISCSI_OP_TEXT:
	case ISCSI_OP_SNACK:
		break;
	default:
		eprintk("unexpected cmnd op %x\n", cmnd_opcode(cmnd));
		break;
	}
}

static void __cmnd_send_pdu(struct iscsi_conn *conn, struct scatterlist *sg,
			    uint32_t offset, uint32_t size)
{
/* 	dprintk(D_GENERIC, "%p %u,%u\n", tio, offset, size); */
	offset += sg->offset;

/* 	assert(offset <= sg->offset + tio->size); */
/* 	assert(offset + size <= tio->offset + tio->size); */

	conn->write_tcmnd = sg;
	conn->write_offset = offset;
	conn->write_size += size;
}

static void cmnd_send_pdu(struct iscsi_conn *conn, struct iscsi_cmnd *cmnd)
{
	uint32_t size;

	if (!cmnd->pdu.datasize)
		return;

	size = (cmnd->pdu.datasize + 3) & -4;
	BUG_ON(!cmnd->sg);
	__cmnd_send_pdu(conn, cmnd->sg, 0, size);
}

static void set_cork(struct socket *sock, int on)
{
	int opt = on;
	mm_segment_t oldfs;

	oldfs = get_fs();
	set_fs(get_ds());
	sock->ops->setsockopt(sock, SOL_TCP, TCP_CORK, (void *)&opt, sizeof(opt));
	set_fs(oldfs);
}

void cmnd_release(struct iscsi_cmnd *cmnd, int force)
{
	struct iscsi_cmnd *req, *rsp;
	int is_last = 0;

	if (!cmnd)
		return;

	req = cmnd->req;
	is_last = cmnd_final(cmnd);

	if (force) {
		while (!list_empty(&cmnd->pdu_list)) {
			rsp = list_entry(cmnd->pdu_list.next, struct iscsi_cmnd, pdu_list);
			list_del_init(&rsp->list);
			list_del(&rsp->pdu_list);
			iscsi_cmnd_remove(rsp);
		}
		list_del_init(&cmnd->list);
	}

	if (cmnd_hashed(cmnd))
		cmnd_remove_hash(cmnd);

	list_del_init(&cmnd->pdu_list);
	iscsi_cmnd_remove(cmnd);

	if (is_last) {
		BUG_ON(force);
		BUG_ON(!req);
		cmnd_release(req, 0);
	}

	return;
}

void cmnd_tx_start(struct iscsi_cmnd *cmnd)
{
	struct iscsi_conn *conn = cmnd->conn;
	struct iovec *iop;

	dprintk("%p:%x\n", cmnd, cmnd_opcode(cmnd));
	BUG_ON(!cmnd);
	iscsi_cmnd_set_length(&cmnd->pdu);

	set_cork(conn->sock, 1);

	conn->write_iop = iop = conn->write_iov;
	iop->iov_base = &cmnd->pdu.bhs;
	iop->iov_len = sizeof(cmnd->pdu.bhs);
	iop++;
	conn->write_size = sizeof(cmnd->pdu.bhs);

	switch (cmnd_opcode(cmnd)) {
	case ISCSI_OP_NOOP_IN:
		cmnd_set_sn(cmnd, 1);
		cmnd_send_pdu(conn, cmnd);
		break;
	case ISCSI_OP_SCSI_CMD_RSP:
		cmnd_set_sn(cmnd, 1);
		cmnd_send_pdu(conn, cmnd);
		break;
	case ISCSI_OP_SCSI_TMFUNC_RSP:
		cmnd_set_sn(cmnd, 1);
		break;
	case ISCSI_OP_TEXT_RSP:
		cmnd_set_sn(cmnd, 1);
		break;
	case ISCSI_OP_SCSI_DATA_IN:
	{
		struct iscsi_data_rsp *rsp = (struct iscsi_data_rsp *)&cmnd->pdu.bhs;
		uint32_t offset;

		cmnd_set_sn(cmnd, (rsp->flags & ISCSI_FLAG_CMD_FINAL) ? 1 : 0);
		offset = rsp->offset;
		rsp->offset = cpu_to_be32(offset);
		BUG_ON(!cmnd->sg);
		__cmnd_send_pdu(conn, cmnd->sg, offset, cmnd->pdu.datasize);
		break;
	}
	case ISCSI_OP_LOGOUT_RSP:
		cmnd_set_sn(cmnd, 1);
		break;
	case ISCSI_OP_R2T:
		cmnd_set_sn(cmnd, 0);
		cmnd->pdu.bhs.statsn = cpu_to_be32(conn->stat_sn);
		break;
	case ISCSI_OP_ASYNC_EVENT:
		cmnd_set_sn(cmnd, 1);
		break;
	case ISCSI_OP_REJECT:
		cmnd_set_sn(cmnd, 1);
		cmnd_send_pdu(conn, cmnd);
		break;
	default:
		eprintk("unexpected cmnd op %x\n", cmnd_opcode(cmnd));
		break;
	}

	iop->iov_len = 0;
	// move this?
	conn->write_size = (conn->write_size + 3) & -4;
}

void cmnd_tx_end(struct iscsi_cmnd *cmnd)
{
	struct iscsi_conn *conn = cmnd->conn;

	dprintk("%p:%x\n", cmnd, cmnd_opcode(cmnd));
	switch (cmnd_opcode(cmnd)) {
	case ISCSI_OP_NOOP_IN:
	case ISCSI_OP_SCSI_CMD_RSP:
	case ISCSI_OP_SCSI_TMFUNC_RSP:
	case ISCSI_OP_TEXT_RSP:
	case ISCSI_OP_R2T:
	case ISCSI_OP_ASYNC_EVENT:
	case ISCSI_OP_REJECT:
	case ISCSI_OP_SCSI_DATA_IN:
	case ISCSI_OP_LOGOUT_RSP:
		break;
	default:
		eprintk("unexpected cmnd op %x\n", cmnd_opcode(cmnd));
		BUG_ON(1);
		break;
	}

	if (cmnd_close(cmnd))
		conn_close(conn);

	list_del_init(&cmnd->list);
	set_cork(cmnd->conn->sock, 0);
}

/**
 * Push the command for execution.
 * This functions reorders the commands.
 * Called from the read thread.
 *
 * iscsi_session_push_cmnd - 
 * @cmnd: ptr to command
 */

static void iscsi_session_push_cmnd(struct iscsi_cmnd *cmnd)
{
	struct iscsi_session *session = cmnd->conn->session;
	struct list_head *entry;
	uint32_t cmd_sn;

	dprintk("%p:%x %u,%u\n",
		cmnd, cmnd_opcode(cmnd), cmnd->pdu.bhs.statsn,
		session->exp_cmd_sn);

	if (cmnd->pdu.bhs.opcode & ISCSI_OP_IMMEDIATE) {
		iscsi_cmnd_exec(cmnd);
		return;
	}

	cmd_sn = cmnd->pdu.bhs.statsn;
	if (cmd_sn == session->exp_cmd_sn) {
		while (1) {
			session->exp_cmd_sn = ++cmd_sn;
			iscsi_cmnd_exec(cmnd);

			if (list_empty(&session->pending_list))
				break;
			cmnd = list_entry(session->pending_list.next, struct iscsi_cmnd, list);
			if (cmnd->pdu.bhs.statsn != cmd_sn)
				break;
/* 			eprintk("find out-of-order %x %u %u\n", */
/* 				cmnd_itt(cmnd), cmd_sn, cmnd->pdu.bhs.statsn); */
			list_del_init(&cmnd->list);
			clear_cmnd_pending(cmnd);
		}
	} else {
/* 		eprintk("out-of-order %x %u %u\n", */
/* 			cmnd_itt(cmnd), cmd_sn, session->exp_cmd_sn); */

		set_cmnd_pending(cmnd);
		if (before(cmd_sn, session->exp_cmd_sn)) /* close the conn */
			eprintk("unexpected cmd_sn (%u,%u)\n", cmd_sn, session->exp_cmd_sn);

		if (after(cmd_sn, session->exp_cmd_sn + session->max_queued_cmnds))
			eprintk("too large cmd_sn (%u,%u)\n", cmd_sn, session->exp_cmd_sn);

		list_for_each(entry, &session->pending_list) {
			struct iscsi_cmnd *tmp = list_entry(entry, struct iscsi_cmnd, list);
			if (before(cmd_sn, tmp->pdu.bhs.statsn))
				break;
		}

		BUG_ON(!list_empty(&cmnd->list));

		list_add_tail(&cmnd->list, entry);
	}
}

static int check_segment_length(struct iscsi_cmnd *cmnd)
{
	struct iscsi_conn *conn = cmnd->conn;
	struct iscsi_sess_param *param = &conn->session->param;

	if (cmnd->pdu.datasize > param->max_recv_data_length) {
		eprintk("too lond data %x %u %u\n", cmnd_itt(cmnd),
			cmnd->pdu.datasize, param->max_recv_data_length);

		if (get_pgcnt(cmnd->pdu.datasize, 0) > ISCSI_CONN_IOV_MAX) {
			conn_close(conn);
			return -EINVAL;
		}
	}

	return 0;
}

void cmnd_rx_start(struct iscsi_cmnd *cmnd)
{
	struct iscsi_conn *conn = cmnd->conn;
	int err = 0;

	if (check_segment_length(cmnd) < 0)
		return;

	switch (cmnd_opcode(cmnd)) {
	case ISCSI_OP_NOOP_OUT:
		err = noop_out_start(conn, cmnd);
		break;
	case ISCSI_OP_SCSI_CMD:
		if (!(err = cmnd_insert_hash(cmnd)))
			scsi_cmnd_start(conn, cmnd);
		break;
	case ISCSI_OP_SCSI_TMFUNC:
		err = cmnd_insert_hash(cmnd);
		break;
	case ISCSI_OP_SCSI_DATA_OUT:
		data_out_start(conn, cmnd);
		break;
	case ISCSI_OP_LOGOUT:
		err = cmnd_insert_hash(cmnd);
		break;
	case ISCSI_OP_TEXT:
	case ISCSI_OP_SNACK:
		err = -CMD_NOT_SUPPORTED;
		break;
	default:
		err = -CMD_NOT_SUPPORTED;
		break;
	}

	if (err < 0) {
		eprintk("%x %x %d\n", cmnd_opcode(cmnd), cmnd_itt(cmnd), err);
		iscsi_cmnd_reject(cmnd, -err);
	}
}

void cmnd_rx_end(struct iscsi_cmnd *cmnd)
{
	struct iscsi_conn *conn = cmnd->conn;

	dprintk("%p:%x\n", cmnd, cmnd_opcode(cmnd));
	switch (cmnd_opcode(cmnd)) {
	case ISCSI_OP_SCSI_REJECT:
	case ISCSI_OP_NOOP_OUT:
	case ISCSI_OP_SCSI_CMD:
	case ISCSI_OP_SCSI_TMFUNC:
	case ISCSI_OP_TEXT:
	case ISCSI_OP_LOGOUT:
		iscsi_session_push_cmnd(cmnd);
		break;
	case ISCSI_OP_SCSI_DATA_OUT:
		data_out_end(conn, cmnd);
		break;
	case ISCSI_OP_SNACK:
		break;
	case ISCSI_OP_PDU_REJECT:
		iscsi_cmnd_init_write(get_rsp_cmnd(cmnd));
		break;
	case ISCSI_OP_DATA_REJECT:
		cmnd_release(cmnd, 0);
		break;
	default:
		eprintk("unexpected cmnd op %x\n", cmnd_opcode(cmnd));
		BUG();
		break;
	}
}

static int buffer_ready(struct tgt_cmd *tc)
{
	struct iscsi_cmnd *cmnd = (struct iscsi_cmnd *) tc->private;

	complete(&cmnd->event);

	return 0;
}


static struct iscsi_sess_param default_session_param = {
	.initial_r2t = 1,
	.immediate_data = 1,
	.max_connections = 1,
	.max_recv_data_length = 8192,
	.max_xmit_data_length = 8192,
	.max_burst_length = 262144,
	.first_burst_length = 65536,
	.default_wait_time = 2,
	.default_retain_time = 20,
	.max_outstanding_r2t = 1,
	.data_pdu_inorder = 1,
	.data_sequence_inorder = 1,
	.error_recovery_level = 0,
	.header_digest = DIGEST_NONE,
	.data_digest = DIGEST_NONE,
	.ofmarker = 0,
	.ifmarker = 0,
	.ofmarkint = 2048,
	.ifmarkint = 2048,
};

static struct iscsi_trgt_param default_target_param = {
	.queued_cmnds = DEFAULT_NR_QUEUED_CMNDS,
};

static int istgt_target_create(struct tgt_target *tt)
{
	int err = -EINVAL;
	struct iscsi_target *target = tt->tt_data;

	target->tt = tt;
	target->tid = target->tt->tid;

	memcpy(&target->sess_param, &default_session_param, sizeof(default_session_param));
	memcpy(&target->trgt_param, &default_target_param, sizeof(default_target_param));

	init_MUTEX(&target->target_sem);
	INIT_LIST_HEAD(&target->session_list);

	nthread_init(target);
	err = nthread_start(target);

	return err;
}

static void istgt_target_destroy(struct tgt_target *tt)
{
	struct iscsi_target *target =
		(struct iscsi_target *) tt->tt_data;

	down(&target->target_sem);

	/* kernel may crash until tgt supports lifetime management. */
	BUG_ON(!list_empty(&target->session_list));

	up(&target->target_sem);

	nthread_stop(target);
}

static struct tgt_target_template istgt_template = {
	.name = THIS_NAME,
	.module = THIS_MODULE,
	.protocol = "scsi",
	.subprotocol = "iscsi",
	.target_create = istgt_target_create,
	.target_destroy = istgt_target_destroy,
	.msg_recv = iet_msg_recv,
	.transfer_response = scsi_cmnd_done,
	.transfer_write_data = buffer_ready,
	.priv_data_size = sizeof(struct iscsi_target),
};

static void istgt_exit(void)
{
	kmem_cache_destroy(istgt_cmd_cache);
	tgt_target_template_unregister(&istgt_template);
}

static int istgt_init(void)
{
	int err;

	printk("iSCSI Target Software for Linux Target Framework %s\n",
	       VERSION_STRING);

	istgt_cmd_cache = kmem_cache_create("istgt_cmd",
					    sizeof(struct iscsi_cmnd),
					    0, 0, NULL, NULL);
	if (!istgt_cmd_cache)
		return -ENOMEM;

	err = tgt_target_template_register(&istgt_template);
	if (err < 0)
		goto free_cmd_cache;

	return 0;

free_cmd_cache:
	kmem_cache_destroy(istgt_cmd_cache);

	return err;
}

module_init(istgt_init);
module_exit(istgt_exit);

MODULE_LICENSE("GPL");
