/*
 * IBM eServer i/pSeries Virtual SCSI Target Driver
 * Copyright (C) 2003-2005 Dave Boutcher (boutcher@us.ibm.com) IBM Corp.
 *			   Santiago Leon (santil@us.ibm.com) IBM Corp.
 *			   Linda Xie (lxie@us.ibm.com) IBM Corp.
 *
 * Copyright (C) 2005 FUJITA Tomonori <tomof@acm.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA
 */

#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/kfifo.h>
#include <scsi/scsi.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_tcq.h>
#include <scsi/scsi_tgt.h>

#include <asm/hvcall.h>
#include <asm/iommu.h>
#include <asm/prom.h>
#include <asm/vio.h>

#include "ibmvscsi.h"

#define	INITIAL_SRP_LIMIT	16
#define	DEFAULT_MAX_SECTORS	512

#define	TGT_NAME	"ibmvstgt"

/*
 * Hypervisor calls.
 */
#define h_copy_rdma(l, sa, sb, da, db) \
			plpar_hcall_norets(H_COPY_RDMA, l, sa, sb, da, db)
#define h_send_crq(ua, l, h) \
			plpar_hcall_norets(H_SEND_CRQ, ua, l, h)
#define h_reg_crq(ua, tok, sz)\
			plpar_hcall_norets(H_REG_CRQ, ua, tok, sz);
#define h_free_crq(ua) \
			plpar_hcall_norets(H_FREE_CRQ, ua);

MODULE_DESCRIPTION("IBM Virtual SCSI Target");
MODULE_AUTHOR("Dave Boutcher");
MODULE_LICENSE("GPL");

/* tmp - will replace with SCSI logging stuff */
#define eprintk(fmt, args...)					\
do {								\
	printk("%s(%d) " fmt, __FUNCTION__, __LINE__, ##args);	\
} while (0)

#define dprintk eprintk
/* #define dprintk(fmt, args...) */

enum iue_flags {
	V_DIOVER,
	V_WRITE,
	V_LINKED,
	V_FLYING,
};

enum srp_task_attributes {
	SRP_SIMPLE_TASK = 0,
	SRP_HEAD_TASK = 1,
	SRP_ORDERED_TASK = 2,
	SRP_ACA_TASK = 4
};

struct srp_buf {
	dma_addr_t dma;
	void *buf;
};

struct srp_queue {
	void *pool;
	void *items;
	struct kfifo *queue;
	spinlock_t lock;
};

struct srp_target {
	struct Scsi_Host *shost;
	struct device *dev;

	spinlock_t lock; /* cmd_queue */
	struct list_head cmd_queue;

	struct srp_queue iu_queue;
	struct srp_buf **rx_ring;

	void *ldata;
};

struct vio_port {
	struct vio_dev *dma_dev;

	struct crq_queue crq_queue;
	struct work_struct crq_work;

	unsigned long liobn;
	unsigned long riobn;
};

struct iu_entry {
	struct srp_target *target;
	struct scsi_cmnd *scmd;

	struct list_head ilist;
	dma_addr_t remote_token;
	unsigned long flags;

	struct srp_buf *sbuf;
};

static struct workqueue_struct *vtgtd;

/*
 * These are fixed for the system and come from the Open Firmware device tree.
 * We just store them here to save getting them every time.
 */
static char system_id[64] = "";
static char partition_name[97] = "UNKNOWN";
static unsigned int partition_number = -1;

static struct srp_target *host_to_target(struct Scsi_Host *host)
{
	return (struct srp_target *) host->hostdata;
}

static struct vio_port *target_to_port(struct srp_target *target)
{
	return (struct vio_port *) target->ldata;
}

static union viosrp_iu *vio_iu(struct iu_entry *iue)
{
	return (union viosrp_iu *) (iue->sbuf->buf);
}

static int iu_pool_alloc(struct srp_queue *q, size_t max, struct srp_buf **ring)
{
	int i;
	struct iu_entry *iue;

	q->pool = kcalloc(max, sizeof(struct iu_entry *), GFP_KERNEL);
	if (!q->pool)
		return -ENOMEM;
	q->items = kcalloc(max, sizeof(struct iu_entry), GFP_KERNEL);
	if (!q->items)
		goto free_pool;

	spin_lock_init(&q->lock);
	q->queue = kfifo_init((void *) q->pool, max * sizeof(void *),
			      GFP_KERNEL, &q->lock);
	if (IS_ERR(q->queue))
		goto free_item;

	for (i = 0, iue = q->items; i < max; i++) {
		__kfifo_put(q->queue, (void *) &iue, sizeof(void *));
		iue->sbuf = ring[i];
		iue++;
	}
	return 0;

free_item:
	kfree(q->items);
free_pool:
	kfree(q->pool);
	return -ENOMEM;
}

static void iu_pool_free(struct srp_queue *q)
{
	kfree(q->items);
	kfree(q->pool);
}

static struct srp_buf ** srp_ring_alloc(struct device *dev,
					size_t max, size_t size)
{
	int i;
	struct srp_buf **ring;

	ring = kcalloc(max, sizeof(struct srp_buf *), GFP_KERNEL);
	if (!ring)
		return NULL;

	for (i = 0; i < max; i++) {
		ring[i] = kzalloc(sizeof(struct srp_buf), GFP_KERNEL);
		if (!ring[i])
			goto out;
		ring[i]->buf = dma_alloc_coherent(dev, size, &ring[i]->dma,
						  GFP_KERNEL);
		if (!ring[i]->buf)
			goto out;
	}
	return ring;

out:
	for (i = 0; i < max && ring[i]; i++) {
		if (ring[i]->buf)
			dma_free_coherent(dev, size, ring[i]->buf, ring[i]->dma);
		kfree(ring[i]);
	}
	kfree(ring);

	return NULL;
}

static void srp_ring_free(struct device *dev, struct srp_buf **ring, size_t max,
			  size_t size)
{
	int i;

	for (i = 0; i < max; i++) {
		dma_free_coherent(dev, size, ring[i]->buf, ring[i]->dma);
		kfree(ring[i]);
	}
}

static int send_iu(struct iu_entry *iue, uint64_t length, uint8_t format)
{
	struct srp_target *target = iue->target;
	struct vio_port *vport = target_to_port(target);
	long rc, rc1;
	union {
		struct viosrp_crq cooked;
		uint64_t raw[2];
	} crq;

	/* First copy the SRP */
	rc = h_copy_rdma(length, vport->liobn, iue->sbuf->dma,
			 vport->riobn, iue->remote_token);

	if (rc)
		eprintk("Error %ld transferring data\n", rc);

	crq.cooked.valid = 0x80;
	crq.cooked.format = format;
	crq.cooked.reserved = 0x00;
	crq.cooked.timeout = 0x00;
	crq.cooked.IU_length = length;
	crq.cooked.IU_data_ptr = vio_iu(iue)->srp.rsp.tag;

	if (rc == 0)
		crq.cooked.status = 0x99;	/* Just needs to be non-zero */
	else
		crq.cooked.status = 0x00;

	rc1 = h_send_crq(vport->dma_dev->unit_address, crq.raw[0], crq.raw[1]);

	if (rc1) {
		eprintk("%ld sending response\n", rc1);
		return rc1;
	}

	return rc;
}

#define SRP_RSP_SENSE_DATA_LEN	18

static int send_rsp(struct iu_entry *iue, unsigned char status,
		    unsigned char asc)
{
	struct srp_target *target = iue->target;
	union viosrp_iu *iu = vio_iu(iue);
	uint64_t tag = iu->srp.rsp.tag;
	unsigned long flags;

	/* If the linked bit is on and status is good */
	if (test_bit(V_LINKED, &iue->flags) && (status == NO_SENSE))
		status = 0x10;

	memset(iu, 0, sizeof(struct srp_rsp));
	iu->srp.rsp.opcode = SRP_RSP;
	spin_lock_irqsave(&target->lock, flags);
	iu->srp.rsp.req_lim_delta = 1;
	spin_unlock_irqrestore(&target->lock, flags);
	iu->srp.rsp.tag = tag;

	if (test_bit(V_DIOVER, &iue->flags))
		iu->srp.rsp.flags |= SRP_RSP_FLAG_DIOVER;

	iu->srp.rsp.data_in_res_cnt = 0;
	iu->srp.rsp.data_out_res_cnt = 0;

	iu->srp.rsp.flags &= ~SRP_RSP_FLAG_RSPVALID;

	iu->srp.rsp.resp_data_len = 0;
	iu->srp.rsp.status = status;
	if (status) {
		uint8_t *sense = iu->srp.rsp.data;

		if (iue->scmd) {
			iu->srp.rsp.flags |= SRP_RSP_FLAG_SNSVALID;
			iu->srp.rsp.sense_data_len = SCSI_SENSE_BUFFERSIZE;
			memcpy(sense, iue->scmd->sense_buffer,
			       SCSI_SENSE_BUFFERSIZE);
		} else {
			iu->srp.rsp.status = SAM_STAT_CHECK_CONDITION;
			iu->srp.rsp.flags |= SRP_RSP_FLAG_SNSVALID;
			iu->srp.rsp.sense_data_len = SRP_RSP_SENSE_DATA_LEN;

			/* Valid bit and 'current errors' */
			sense[0] = (0x1 << 7 | 0x70);
			/* Sense key */
			sense[2] = status;
			/* Additional sense length */
			sense[7] = 0xa;	/* 10 bytes */
			/* Additional sense code */
			sense[12] = asc;
		}
	}

	send_iu(iue, sizeof(iu->srp.rsp) + SRP_RSP_SENSE_DATA_LEN,
		VIOSRP_SRP_FORMAT);

	return 0;
}

static int data_out_desc_size(struct srp_cmd *cmd)
{
	int size = 0;
	u8 fmt = cmd->buf_fmt >> 4;

	switch (fmt) {
	case SRP_NO_DATA_DESC:
		break;
	case SRP_DATA_DESC_DIRECT:
		size = sizeof(struct srp_direct_buf);
		break;
	case SRP_DATA_DESC_INDIRECT:
		size = sizeof(struct srp_indirect_buf) +
			sizeof(struct srp_direct_buf) * cmd->data_out_desc_cnt;
		break;
	default:
		eprintk("client error. Invalid data_out_format %x\n", fmt);
		break;
	}
	return size;
}

static int vscsis_data_length(struct srp_cmd *cmd, enum dma_data_direction dir)
{
	struct srp_direct_buf *md;
	struct srp_indirect_buf *id;
	int len = 0, offset = cmd->add_cdb_len * 4;
	u8 fmt;

	if (dir == DMA_TO_DEVICE)
		fmt = cmd->buf_fmt >> 4;
	else {
		fmt = cmd->buf_fmt & ((1U << 4) - 1);
		offset += data_out_desc_size(cmd);
	}

	switch (fmt) {
	case SRP_NO_DATA_DESC:
		break;
	case SRP_DATA_DESC_DIRECT:
		md = (struct srp_direct_buf *) (cmd->add_data + offset);
		len = md->len;
		break;
	case SRP_DATA_DESC_INDIRECT:
		id = (struct srp_indirect_buf *) (cmd->add_data + offset);
		len = id->len;
		break;
	default:
		eprintk("invalid data format %x\n", fmt);
		break;
	}
	return len;
}

static uint8_t getcontrolbyte(uint8_t *cdb)
{
	return cdb[COMMAND_SIZE(cdb[0]) - 1];
}

static inline uint8_t getlink(struct iu_entry *iue)
{
	return (getcontrolbyte(vio_iu(iue)->srp.cmd.cdb) & 0x01);
}

static int process_cmd(struct iu_entry *iue)
{
	struct Scsi_host *shost = iue->target->shost;
	union viosrp_iu *iu = vio_iu(iue);
	enum dma_data_direction data_dir;
	struct scsi_cmnd *scmd;
	int tag, len;

	dprintk("%p %p\n", iue->target, iue);

	if (getlink(iue))
		__set_bit(V_LINKED, &iue->flags);

	tag = MSG_SIMPLE_TAG;

	switch (iu->srp.cmd.task_attr) {
	case SRP_SIMPLE_TASK:
		tag = MSG_SIMPLE_TAG;
		break;
	case SRP_ORDERED_TASK:
		tag = MSG_ORDERED_TAG;
		break;
	case SRP_HEAD_TASK:
		tag = MSG_HEAD_TAG;
		break;
	default:
		eprintk("Task attribute %d not supported, assuming barrier\n",
			iu->srp.cmd.task_attr);
		tag = MSG_ORDERED_TAG;
	}

	switch (iu->srp.cmd.cdb[0]) {
	case WRITE_6:
	case WRITE_10:
	case WRITE_VERIFY:
	case WRITE_12:
	case WRITE_VERIFY_12:
		__set_bit(V_WRITE, &iue->flags);
	}

	if (iu->srp.cmd.buf_fmt >> 4)
		data_dir = DMA_TO_DEVICE;
	else
		data_dir = DMA_FROM_DEVICE;
	len = vscsis_data_length(&iu->srp.cmd, data_dir);

	dprintk("%p %x %lx %d %d %d %llx\n",
		iue, iu->srp.cmd.cdb[0], iu->srp.cmd.lun, data_dir, len, tag,
		(unsigned long long) iu->srp.cmd.tag);

	scmd = scsi_host_get_command(shost, data_dir, GFP_KERNEL);
	BUG_ON(!scmd);

	scmd->SCp.ptr = (char *) iue;
	memcpy(scmd->data_cmnd, iu->srp.cmd.cdb, MAX_COMMAND_SIZE);
	scmd->request_bufflen = len;
	scmd->tag= tag;
	iue->scmd = scmd;
	scsi_tgt_queue_command(scmd, (struct scsi_lun *) &iu->srp.cmd.lun,
			       iu->srp.cmd.tag);

	dprintk("%p %p %x %lx %d %d %d\n",
		iue, scmd, iu->srp.cmd.cdb[0], iu->srp.cmd.lun, data_dir, len, tag);

	return 0;
}

static void handle_cmd_queue(struct srp_target *target)
{
	struct iu_entry *iue;
	unsigned long flags;

retry:
	spin_lock_irqsave(&target->lock, flags);

	list_for_each_entry(iue, &target->cmd_queue, ilist) {
		if (!test_and_set_bit(V_FLYING, &iue->flags)) {
			spin_unlock_irqrestore(&target->lock, flags);
			process_cmd(iue);
			goto retry;
		}
	}

	spin_unlock_irqrestore(&target->lock, flags);
}

static int direct_data(struct scsi_cmnd *scmd, struct srp_direct_buf *md,
		       enum dma_data_direction dir)
{
	struct iu_entry *iue = (struct iu_entry *) scmd->SCp.ptr;
	struct srp_target *target = iue->target;
	struct vio_port *vport = target_to_port(target);
	struct scatterlist *sg = scmd->request_buffer;
	unsigned int rest, len;
	int i, done, nsg;
	long err;
	dma_addr_t token;

	dprintk("%p %u %u %u %d\n", iue, scmd->request_bufflen, scmd->bufflen,
		md->len, scmd->use_sg);

	nsg = dma_map_sg(target->dev, sg, scmd->use_sg, DMA_BIDIRECTIONAL);
	if (!nsg) {
		eprintk("fail to map %p %d\n", iue, scmd->use_sg);
		return 0;
	}

	rest = min(scmd->request_bufflen, md->len);

	for (i = 0, done = 0; i < nsg && rest; i++) {
		token = sg_dma_address(sg + i);
		len = min(sg_dma_len(sg + i), rest);

		if (dir == DMA_TO_DEVICE)
			err = h_copy_rdma(len, vport->riobn, md->va + done,
					  vport->liobn, token);
		else
			err = h_copy_rdma(len, vport->liobn, token,
					  vport->riobn, md->va + done);

		if (err != H_Success) {
			eprintk("rdma error %d %d %ld\n", dir, i, err);
			break;
		}

		rest -= len;
		done += len;
	}

	dma_unmap_sg(target->dev, sg, nsg, DMA_BIDIRECTIONAL);

	return done;
}

static int indirect_data(struct scsi_cmnd *scmd, struct srp_indirect_buf *id,
			 enum dma_data_direction dir)
{
	struct iu_entry *iue = (struct iu_entry *) scmd->SCp.ptr;
	struct srp_target *target = iue->target;
	struct vio_port *vport = target_to_port(target);
	struct srp_cmd *cmd = &vio_iu(iue)->srp.cmd;
	struct srp_direct_buf *mds;
	struct scatterlist *sg = scmd->request_buffer;
	dma_addr_t token, itoken = 0;
	long err;
	unsigned int rest, done = 0;
	int i, nmd, nsg, sidx, soff;

	nmd = id->table_desc.len / sizeof(struct srp_direct_buf);

	dprintk("%p %u %u %u %u %d %d %d\n",
		iue, scmd->request_bufflen, scmd->bufflen,
		id->len, scmd->offset, nmd,
		cmd->data_in_desc_cnt, cmd->data_out_desc_cnt);

	if ((dir == DMA_FROM_DEVICE && nmd == cmd->data_in_desc_cnt) ||
	    (dir == DMA_TO_DEVICE && nmd == cmd->data_out_desc_cnt)) {
		mds = &id->desc_list[0];
		goto rdma;
	}

	mds = dma_alloc_coherent(target->dev, id->table_desc.len,
				 &itoken, GFP_KERNEL);
	if (!mds) {
		eprintk("Can't get dma memory %u\n", id->table_desc.len);
		return 0;
	}

	err = h_copy_rdma(id->table_desc.len, vport->riobn,
			  id->table_desc.va, vport->liobn, itoken);
	if (err != H_Success) {
		eprintk("Error copying indirect table %ld\n", err);
		goto free_mem;
	}

rdma:
	nsg = dma_map_sg(target->dev, sg, scmd->use_sg, DMA_BIDIRECTIONAL);
	if (!nsg) {
		eprintk("fail to map %p %d\n", iue, scmd->use_sg);
		goto free_mem;
	}

	sidx = soff = 0;
	token = sg_dma_address(sg + sidx);
	rest = min(scmd->request_bufflen, id->len);
	for (i = 0; i < nmd && rest; i++) {
		unsigned int mdone, mlen;

		mlen = min(rest, mds[i].len);
		for (mdone = 0; mlen;) {
			int slen = min(sg_dma_len(sg + sidx) - soff, mlen);

			if (dir == DMA_TO_DEVICE)
				err = h_copy_rdma(slen,
						  vport->riobn,
						  mds[i].va + mdone,
						  vport->liobn,
						  token + soff);
			else
				err = h_copy_rdma(slen,
						  vport->liobn,
						  token + soff,
						  vport->riobn,
						  mds[i].va + mdone);

			if (err != H_Success) {
				eprintk("rdma error %d %d\n", dir, slen);
				goto unmap_sg;
			}

			mlen -= slen;
			mdone += slen;
			soff += slen;
			done += slen;

			if (soff == sg_dma_len(sg + sidx)) {
				sidx++;
				soff = 0;
				token = sg_dma_address(sg + sidx);

				if (sidx > nsg) {
					eprintk("out of sg %p %d %d %d\n",
						iue, sidx, nsg, scmd->use_sg);
					goto unmap_sg;
				}
			}
		};

		rest -= mlen;
	}

unmap_sg:
	dma_unmap_sg(target->dev, sg, nsg, DMA_BIDIRECTIONAL);

free_mem:
	if (itoken)
		dma_free_coherent(target->dev, id->table_desc.len, mds, itoken);

	return done;
}

static int handle_cmd_data(struct scsi_cmnd *scmd, enum dma_data_direction dir)
{
	struct iu_entry *iue = (struct iu_entry *) scmd->SCp.ptr;
	struct srp_cmd *cmd = &vio_iu(iue)->srp.cmd;
	struct srp_direct_buf *md;
	struct srp_indirect_buf *id;
	int offset, err = 0;
	u8 format;

	offset = cmd->add_cdb_len * 4;
	if (dir == DMA_FROM_DEVICE)
		offset += data_out_desc_size(cmd);

	if (dir == DMA_TO_DEVICE)
		format = cmd->buf_fmt >> 4;
	else
		format = cmd->buf_fmt & ((1U << 4) - 1);

	switch (format) {
	case SRP_NO_DATA_DESC:
		break;
	case SRP_DATA_DESC_DIRECT:
		md = (struct srp_direct_buf *)
			(cmd->add_data + offset);
		err = direct_data(scmd, md, dir);
		break;
	case SRP_DATA_DESC_INDIRECT:
		id = (struct srp_indirect_buf *)
			(cmd->add_data + offset);
		err = indirect_data(scmd, id, dir);
		break;
	default:
		eprintk("Unknown format %d %x\n", dir, format);
		break;
	}

	return err;
}

/* TODO: this can be called multiple times for a single command. */
static int recv_cmd_data(struct scsi_cmnd *scmd,
			 void (*done)(struct scsi_cmnd *))
{
	struct iu_entry	*iue = (struct iu_entry *) scmd->SCp.ptr;
	enum dma_data_direction dir;

	if (test_bit(V_WRITE, &iue->flags))
		dir = DMA_TO_DEVICE;
	else
		dir = DMA_FROM_DEVICE;
	handle_cmd_data(scmd, dir);
	done(scmd);
	return 0;
}

static struct iu_entry *get_iu(struct srp_target *target)
{
	struct iu_entry *iue = NULL;

	kfifo_get(target->iu_queue.queue, (void *) &iue, sizeof(void *));
	BUG_ON(!iue);

	iue->target = target;
	iue->scmd = NULL;
	INIT_LIST_HEAD(&iue->ilist);
	iue->flags = 0;

	return iue;
}

static void put_iu(struct iu_entry *iue)
{
	kfifo_put(iue->target->iu_queue.queue, (void *) &iue, sizeof(void *));
}

static int ibmvstgt_cmd_done(struct scsi_cmnd *scmd,
			     void (*done)(struct scsi_cmnd *))
{
	unsigned long flags;
	struct iu_entry *iue = (struct iu_entry *) scmd->SCp.ptr;
	struct srp_target *target = iue->target;

	dprintk("%p %p %x\n", iue, target, vio_iu(iue)->srp.cmd.cdb[0]);

	spin_lock_irqsave(&target->lock, flags);
	list_del(&iue->ilist);
	spin_unlock_irqrestore(&target->lock, flags);

	if (scmd->result != SAM_STAT_GOOD) {
		eprintk("operation failed %p %d %x\n",
			iue, scmd->result, vio_iu(iue)->srp.cmd.cdb[0]);
		send_rsp(iue, HARDWARE_ERROR, 0x00);
	} else
		send_rsp(iue, NO_SENSE, 0x00);

	done(scmd);
	put_iu(iue);
	return 0;
}

int send_adapter_info(struct iu_entry *iue,
		      dma_addr_t remote_buffer, uint16_t length)
{
	struct srp_target *target = iue->target;
	struct vio_port *vport = target_to_port(target);
	struct Scsi_Host *shost = target->shost;
	dma_addr_t data_token;
	struct mad_adapter_info_data *info;
	int err;

	info = dma_alloc_coherent(target->dev, sizeof(*info), &data_token,
				  GFP_KERNEL);
	if (!info) {
		eprintk("bad dma_alloc_coherent %p\n", target);
		return 1;
	}

	/* Get remote info */
	err = h_copy_rdma(sizeof(*info), vport->riobn, remote_buffer,
			  vport->liobn, data_token);
	if (err == H_Success) {
		eprintk("Client connect: %s (%d)\n",
			info->partition_name, info->partition_number);
	}

	memset(info, 0, sizeof(*info));

	strcpy(info->srp_version, "16.a");
	strncpy(info->partition_name, partition_name,
		sizeof(info->partition_name));
	info->partition_number = partition_number;
	info->mad_version = 1;
	info->os_type = 2;
	info->port_max_txu[0] = shost->hostt->max_sectors << 9;

	/* Send our info to remote */
	err = h_copy_rdma(sizeof(*info), vport->liobn, data_token,
			  vport->riobn, remote_buffer);

	dma_free_coherent(target->dev, sizeof(*info), info, data_token);

	if (err != H_Success) {
		eprintk("Error sending adapter info %d\n", err);
		return 1;
	}

	return 0;
}

static void process_login(struct iu_entry *iue)
{
	union viosrp_iu *iu = vio_iu(iue);
	struct srp_login_rsp *rsp = &iu->srp.login_rsp;

	uint64_t tag = iu->srp.rsp.tag;

	/* TODO handle case that requested size is wrong and
	 * buffer format is wrong
	 */
	memset(iu, 0, sizeof(struct srp_login_rsp));
	rsp->opcode = SRP_LOGIN_RSP;
	rsp->req_lim_delta = INITIAL_SRP_LIMIT;
	rsp->tag = tag;
	rsp->max_it_iu_len = sizeof(union srp_iu);
	rsp->max_ti_iu_len = sizeof(union srp_iu);
	/* direct and indirect */
	rsp->buf_fmt = SRP_BUF_FORMAT_DIRECT | SRP_BUF_FORMAT_INDIRECT;

	send_iu(iue, sizeof(*rsp), VIOSRP_SRP_FORMAT);
}

static inline void queue_cmd(struct iu_entry *iue)
{
	struct srp_target *target = iue->target;
	unsigned long flags;

	spin_lock_irqsave(&target->lock, flags);
	list_add_tail(&iue->ilist, &target->cmd_queue);
	spin_unlock_irqrestore(&target->lock, flags);
	handle_cmd_queue(target);
}

static int process_tsk_mgmt(struct iu_entry *iue)
{
	union viosrp_iu *iu = vio_iu(iue);
	int fn;

	eprintk("%p %u\n", iue, iu->srp.tsk_mgmt.tsk_mgmt_func);

	switch (iu->srp.tsk_mgmt.tsk_mgmt_func) {
	case SRP_TSK_ABORT_TASK:
		fn = ABORT_TASK;
		break;
	case SRP_TSK_ABORT_TASK_SET:
		fn = ABORT_TASK_SET;
		break;
	case SRP_TSK_CLEAR_TASK_SET:
		fn = CLEAR_TASK_SET;
		break;
	case SRP_TSK_LUN_RESET:
		fn = LOGICAL_UNIT_RESET;
		break;
	case SRP_TSK_CLEAR_ACA:
		fn = CLEAR_ACA;
		break;
	default:
		fn = 0;
	}
	if (fn)
		scsi_tgt_tsk_mgmt_request(iue->target->shost, fn,
					  iu->srp.tsk_mgmt.task_tag,
					  (struct scsi_lun *) &iu->srp.tsk_mgmt.lun,
					  iue);
	else
		send_rsp(iue, ILLEGAL_REQUEST, 0x20);

	return !fn;
}

static int process_mad_iu(struct iu_entry *iue)
{
	union viosrp_iu *iu = vio_iu(iue);
	struct viosrp_adapter_info *info;
	struct viosrp_host_config *conf;

	dprintk("%p %d\n", iue, iu->mad.empty_iu.common.type);

	switch (iu->mad.empty_iu.common.type) {
	case VIOSRP_EMPTY_IU_TYPE:
		eprintk("%s\n", "Unsupported EMPTY MAD IU");
		break;
	case VIOSRP_ERROR_LOG_TYPE:
		eprintk("%s\n", "Unsupported ERROR LOG MAD IU");
		iu->mad.error_log.common.status = 1;
		send_iu(iue, sizeof(iu->mad.error_log),	VIOSRP_MAD_FORMAT);
		break;
	case VIOSRP_ADAPTER_INFO_TYPE:
		info = &iu->mad.adapter_info;

		info->common.status = send_adapter_info(iue, info->buffer,
							info->common.length);
		send_iu(iue, sizeof(*info), VIOSRP_MAD_FORMAT);
		break;
	case VIOSRP_HOST_CONFIG_TYPE:
		conf = &iu->mad.host_config;

		conf->common.status = 1;
		send_iu(iue, sizeof(*conf), VIOSRP_MAD_FORMAT);
		break;
	default:
		eprintk("Unknown type %u\n", iu->srp.rsp.opcode);
	}

	return 1;
}

static int process_srp_iu(struct iu_entry *iue)
{
	union viosrp_iu *iu = vio_iu(iue);
	int done = 1;
	u8 opcode = iu->srp.rsp.opcode;

	dprintk("%p %u\n", iue, opcode);

	switch (opcode) {
	case SRP_LOGIN_REQ:
		process_login(iue);
		break;
	case SRP_TSK_MGMT:
		done = process_tsk_mgmt(iue);
		break;
	case SRP_CMD:
		queue_cmd(iue);
		done = 0;
		break;
	case SRP_LOGIN_RSP:
	case SRP_I_LOGOUT:
	case SRP_T_LOGOUT:
	case SRP_RSP:
	case SRP_CRED_REQ:
	case SRP_CRED_RSP:
	case SRP_AER_REQ:
	case SRP_AER_RSP:
		eprintk("Unsupported type %u\n", opcode);
		break;
	default:
		eprintk("Unknown type %u\n", opcode);
	}

	return done;
}

static void process_iu(struct viosrp_crq *crq, struct srp_target *target)
{
	struct vio_port *vport = target_to_port(target);
	struct iu_entry *iue;
	long err, done;

	iue = get_iu(target);
	if (!iue) {
		eprintk("Error getting IU from pool, %p\n", target);
		return;
	}

	dprintk("%p %p\n", target, iue);

	iue->remote_token = crq->IU_data_ptr;

	err = h_copy_rdma(crq->IU_length, vport->riobn,
			  iue->remote_token, vport->liobn, iue->sbuf->dma);

	if (err != H_Success)
		eprintk("%ld transferring data error %p\n", err, iue);

	if (crq->format == VIOSRP_MAD_FORMAT)
		done = process_mad_iu(iue);
	else
		done = process_srp_iu(iue);

	if (done)
		put_iu(iue);
}

static irqreturn_t ibmvstgt_interrupt(int irq, void *data, struct pt_regs *regs)
{
	struct srp_target *target = (struct srp_target *) data;
	struct vio_port *vport = target_to_port(target);

	vio_disable_interrupts(vport->dma_dev);
	queue_work(vtgtd, &vport->crq_work);

	return IRQ_HANDLED;
}

static int crq_queue_create(struct crq_queue *queue, struct srp_target *target)
{
	int err;
	struct vio_port *vport = target_to_port(target);

	queue->msgs = (struct viosrp_crq *) get_zeroed_page(GFP_KERNEL);
	if (!queue->msgs)
		goto malloc_failed;
	queue->size = PAGE_SIZE / sizeof(*queue->msgs);

	queue->msg_token = dma_map_single(target->dev, queue->msgs,
					  queue->size * sizeof(*queue->msgs),
					  DMA_BIDIRECTIONAL);

	if (dma_mapping_error(queue->msg_token))
		goto map_failed;

	err = h_reg_crq(vport->dma_dev->unit_address, queue->msg_token,
			PAGE_SIZE);

	/* If the adapter was left active for some reason (like kexec)
	 * try freeing and re-registering
	 */
	if (err == H_Resource) {
	    do {
		err = h_free_crq(vport->dma_dev->unit_address);
	    } while (err == H_Busy || H_isLongBusy(err));

	    err = h_reg_crq(vport->dma_dev->unit_address, queue->msg_token,
			    PAGE_SIZE);
	}

	if (err != H_Success && err != 2) {
		eprintk("Error 0x%x opening virtual adapter\n", err);
		goto reg_crq_failed;
	}

	err = request_irq(vport->dma_dev->irq, &ibmvstgt_interrupt,
			  SA_INTERRUPT, "ibmvstgt", target);
	if (err)
		goto req_irq_failed;

	vio_enable_interrupts(vport->dma_dev);

	h_send_crq(vport->dma_dev->unit_address, 0xC001000000000000, 0);

	queue->cur = 0;
	spin_lock_init(&queue->lock);

	return 0;

req_irq_failed:
	do {
		err = h_free_crq(vport->dma_dev->unit_address);
	} while (err == H_Busy || H_isLongBusy(err));

reg_crq_failed:
	dma_unmap_single(target->dev, queue->msg_token,
			 queue->size * sizeof(*queue->msgs), DMA_BIDIRECTIONAL);
map_failed:
	free_page((unsigned long) queue->msgs);

malloc_failed:
	return -ENOMEM;
}

static void crq_queue_destroy(struct srp_target *target)
{
	struct vio_port *vport = target_to_port(target);
	struct crq_queue *queue = &vport->crq_queue;
	int err;

	free_irq(vport->dma_dev->irq, target);
	do {
		err = h_free_crq(vport->dma_dev->unit_address);
	} while (err == H_Busy || H_isLongBusy(err));

	dma_unmap_single(target->dev, queue->msg_token,
			 queue->size * sizeof(*queue->msgs), DMA_BIDIRECTIONAL);

	free_page((unsigned long) queue->msgs);
}

static void process_crq(struct viosrp_crq *crq,	struct srp_target *target)
{
	struct vio_port *vport = target_to_port(target);
	dprintk("%x %x\n", crq->valid, crq->format);

	switch (crq->valid) {
	case 0xC0:
		/* initialization */
		switch (crq->format) {
		case 0x01:
			h_send_crq(vport->dma_dev->unit_address,
				   0xC002000000000000, 0);
			break;
		case 0x02:
			break;
		default:
			eprintk("Unknown format %u\n", crq->format);
		}
		break;
	case 0xFF:
		/* transport event */
		break;
	case 0x80:
		/* real payload */
		switch (crq->format) {
		case VIOSRP_SRP_FORMAT:
		case VIOSRP_MAD_FORMAT:
			process_iu(crq, target);
			break;
		case VIOSRP_OS400_FORMAT:
		case VIOSRP_AIX_FORMAT:
		case VIOSRP_LINUX_FORMAT:
		case VIOSRP_INLINE_FORMAT:
			eprintk("Unsupported format %u\n", crq->format);
			break;
		default:
			eprintk("Unknown format %u\n", crq->format);
		}
		break;
	default:
		eprintk("unknown message type 0x%02x!?\n", crq->valid);
	}
}

static inline struct viosrp_crq *next_crq(struct crq_queue *queue)
{
	struct viosrp_crq *crq;
	unsigned long flags;

	spin_lock_irqsave(&queue->lock, flags);
	crq = &queue->msgs[queue->cur];
	if (crq->valid & 0x80) {
		if (++queue->cur == queue->size)
			queue->cur = 0;
	} else
		crq = NULL;
	spin_unlock_irqrestore(&queue->lock, flags);

	return crq;
}

static void handle_crq(void *data)
{
	struct srp_target *target = (struct srp_target *) data;
	struct vio_port *vport = target_to_port(target);
	struct viosrp_crq *crq;
	int done = 0;

	while (!done) {
		while ((crq = next_crq(&vport->crq_queue)) != NULL) {
			process_crq(crq, target);
			crq->valid = 0x00;
		}

		vio_enable_interrupts(vport->dma_dev);

		crq = next_crq(&vport->crq_queue);
		if (crq) {
			vio_disable_interrupts(vport->dma_dev);
			process_crq(crq, target);
			crq->valid = 0x00;
		} else
			done = 1;
	}

	handle_cmd_queue(target);
}

static int ibmvstgt_eh_abort_handler(struct scsi_cmnd *scmd)
{
	unsigned long flags;
	struct iu_entry *iue = (struct iu_entry *) scmd->SCp.ptr;
	struct srp_target *target = iue->target;

	dprintk("%p %p %x\n", iue, target, vio_iu(iue)->srp.cmd.cdb[0]);

	spin_lock_irqsave(&target->lock, flags);
	list_del(&iue->ilist);
	spin_unlock_irqrestore(&target->lock, flags);

	put_iu(iue);

	return 0;
}

static int ibmvstgt_tsk_mgmt_response(u64 mid, int result)
{
	struct iu_entry *iue = (struct iu_entry *) ((void *) mid);
	union viosrp_iu *iu = vio_iu(iue);
	unsigned char status, asc;

	eprintk("%p %d\n", iue, result);
	status = NO_SENSE;
	asc = 0;

	switch (iu->srp.tsk_mgmt.tsk_mgmt_func) {
	case SRP_TSK_ABORT_TASK:
		asc = 0x14;
		if (result)
			status = ABORTED_COMMAND;
		break;
	default:
		break;
	}

	send_rsp(iue, status, asc);
	put_iu(iue);

	return 0;
}

static ssize_t
system_id_show(struct class_device *cdev, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%s\n", system_id);
}

static ssize_t
partition_number_show(struct class_device *cdev, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%x\n", partition_number);
}

static ssize_t
unit_address_show(struct class_device *cdev, char *buf)
{
	struct Scsi_Host *shost = class_to_shost(cdev);
	struct srp_target *target = host_to_target(shost);
	struct vio_port *vport = target_to_port(target);
	return snprintf(buf, PAGE_SIZE, "%x\n", vport->dma_dev->unit_address);
}

static CLASS_DEVICE_ATTR(system_id, S_IRUGO, system_id_show, NULL);
static CLASS_DEVICE_ATTR(partition_number, S_IRUGO, partition_number_show, NULL);
static CLASS_DEVICE_ATTR(unit_address, S_IRUGO, unit_address_show, NULL);

static struct class_device_attribute *ibmvstgt_attrs[] = {
	&class_device_attr_system_id,
	&class_device_attr_partition_number,
	&class_device_attr_unit_address,
	NULL,
};

static struct scsi_host_template ibmvstgt_sht = {
	.name			= TGT_NAME,
	.module			= THIS_MODULE,
	.can_queue		= INITIAL_SRP_LIMIT,
	.sg_tablesize		= SG_ALL,
	.use_clustering		= DISABLE_CLUSTERING,
	.max_sectors		= DEFAULT_MAX_SECTORS,
	.transfer_response	= ibmvstgt_cmd_done,
	.transfer_data		= recv_cmd_data,
	.eh_abort_handler	= ibmvstgt_eh_abort_handler,
	.tsk_mgmt_response	= ibmvstgt_tsk_mgmt_response,
	.shost_attrs		= ibmvstgt_attrs,
	.proc_name		= TGT_NAME,
};

static int ibmvstgt_probe(struct vio_dev *dev, const struct vio_device_id *id)
{
	struct Scsi_Host *shost;
	struct srp_target *target;
	struct vio_port *vport;
	unsigned int *dma, dma_size;
	int err = -ENOMEM;

	dprintk("%s %s %x %u\n", dev->name, dev->type,
		dev->unit_address, dev->irq);

	vport = kzalloc(sizeof(struct vio_port), GFP_KERNEL);
	if (!vport)
		return err;
	shost = scsi_host_alloc(&ibmvstgt_sht, sizeof(struct srp_target));
	if (!shost)
		goto free_vport;
	if (scsi_tgt_alloc_queue(shost))
		goto put_host;

	target = host_to_target(shost);
	target->shost = shost;
	vport->dma_dev = dev;
	target->dev = &dev->dev;
	target->dev->driver_data = target;
	spin_lock_init(&target->lock);
	INIT_LIST_HEAD(&target->cmd_queue);
	target->ldata = vport;

	dma = (unsigned int *)
		vio_get_attribute(dev, "ibm,my-dma-window", &dma_size);
	if (!dma || dma_size != 40) {
		eprintk("Couldn't get window property %d\n", dma_size);
		err = -EIO;
		goto put_host;
	}
	vport->liobn = dma[0];
	vport->riobn = dma[5];

	INIT_WORK(&vport->crq_work, handle_crq, target);

	target->rx_ring = srp_ring_alloc(target->dev, INITIAL_SRP_LIMIT,
					  SRP_MAX_IU_LEN);
	if (!target->rx_ring)
		goto put_host;
	err = iu_pool_alloc(&target->iu_queue, INITIAL_SRP_LIMIT,
			    target->rx_ring);
	if (err)
		goto free_ring;

	err = crq_queue_create(&vport->crq_queue, target);
	if (err)
		goto free_pool;

	if (scsi_add_host(shost, target->dev))
		goto destroy_queue;
	return 0;

destroy_queue:
	crq_queue_destroy(target);
free_pool:
	iu_pool_free(&target->iu_queue);
free_ring:
	srp_ring_free(target->dev, target->rx_ring, INITIAL_SRP_LIMIT,
		      SRP_MAX_IU_LEN);
put_host:
	scsi_host_put(shost);
free_vport:
	kfree(vport);
	return err;
}

static int ibmvstgt_remove(struct vio_dev *dev)
{
	struct srp_target *target = (struct srp_target *) dev->dev.driver_data;
	struct Scsi_Host *shost = target->shost;

	crq_queue_destroy(target);
	srp_ring_free(target->dev, target->rx_ring, INITIAL_SRP_LIMIT,
		      SRP_MAX_IU_LEN);
	iu_pool_free(&target->iu_queue);
	scsi_remove_host(shost);
	scsi_host_put(shost);
	return 0;
}

static struct vio_device_id ibmvstgt_device_table[] __devinitdata = {
	{"v-scsi-host", "IBM,v-scsi-host"},
	{"",""}
};

MODULE_DEVICE_TABLE(vio, ibmvstgt_device_table);

static struct vio_driver ibmvstgt_driver = {
	.id_table = ibmvstgt_device_table,
	.probe = ibmvstgt_probe,
	.remove = ibmvstgt_remove,
	.driver = {
		.name = "ibmvscsi",
		.owner = THIS_MODULE,
	}
};

static int get_system_info(void)
{
	struct device_node *rootdn;
	char *id, *model, *name;
	unsigned int *num;

	rootdn = find_path_device("/");
	if (!rootdn)
		return -ENOENT;

	model = get_property(rootdn, "model", NULL);
	id = get_property(rootdn, "system-id", NULL);
	if (model && id)
		snprintf(system_id, sizeof(system_id), "%s-%s", model, id);

	name = get_property(rootdn, "ibm,partition-name", NULL);
	if (name)
		strncpy(partition_name, name, sizeof(partition_name));

	num = (unsigned int *) get_property(rootdn, "ibm,partition-no", NULL);
	if (num)
		partition_number = *num;

	return 0;
}

static int ibmvstgt_init(void)
{
	int err = -ENOMEM;

	printk("IBM eServer i/pSeries Virtual SCSI Target Driver\n");

	vtgtd = create_workqueue("ibmvtgtd");
	if (!vtgtd)
		return err;

	err = get_system_info();
	if (err < 0)
		goto destroy_wq;

	err = vio_register_driver(&ibmvstgt_driver);
	if (err)
		goto destroy_wq;

	return 0;

destroy_wq:
	destroy_workqueue(vtgtd);
	return err;
}

static void ibmvstgt_exit(void)
{
	printk("Unregister IBM virtual SCSI driver\n");

	destroy_workqueue(vtgtd);
	vio_unregister_driver(&ibmvstgt_driver);
}

module_init(ibmvstgt_init);
module_exit(ibmvstgt_exit);
