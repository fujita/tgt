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
#include <linux/mempool.h>
#include <scsi/scsi.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_tcq.h>
#include <scsi/scsi_tgt.h>

#include <asm/hvcall.h>
#include <asm/iommu.h>
#include <asm/prom.h>
#include <asm/vio.h>

#include "viosrp.h"
#include "srp.h"

#define DEFAULT_TIMEOUT		30*HZ
#define	INITIAL_SRP_LIMIT	16
#define	DEFAULT_MAX_SECTORS	512

#define	TGT_NAME	"ibmvstgt"

#define	vio_iu(iue)\
	((union viosrp_iu *) ((char *) (iue) + sizeof(struct iu_entry)))

#define GETBUS(x) ((int)((((uint64_t)(x)) >> 53) & 0x0007))
#define GETTARGET(x) ((int)((((uint64_t)(x)) >> 56) & 0x003f))
#define GETLUN(x) ((int)((((uint64_t)(x)) >> 48) & 0x001f))

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
#define dprintk(fmt, args...)					\
do {								\
	printk("%s(%d) " fmt, __FUNCTION__, __LINE__, ##args);	\
} while (0)

#define eprintk dprintk

/*
 * an RPA command/response transport queue.  This is our structure
 * that points to the actual queue (not architected by firmware)
 */
struct crq_queue {
	struct viosrp_crq *msgs;
	int size, cur;
	dma_addr_t msg_token;
	spinlock_t lock;
};

/* all driver data associated with a host adapter */
struct server_adapter {
	struct device *dev;
	struct vio_dev *dma_dev;

	struct crq_queue crq_queue;
	struct work_struct crq_work;
	mempool_t *iu_pool;

	spinlock_t lock; /* cmd_queue and next_rsp_delta */
	struct list_head cmd_queue;
	int next_rsp_delta;

	unsigned long liobn;
	unsigned long riobn;

	struct Scsi_Host *shost;
};

enum iue_flags {
	V_DIOVER,
	V_WRITE,
	V_LINKED,
	V_ABORTED,
	V_FLYING,
	V_DONE,
};

enum srp_task_attributes {
	SRP_SIMPLE_TASK = 0,
	SRP_HEAD_TASK = 1,
	SRP_ORDERED_TASK = 2,
	SRP_ACA_TASK = 4
};

/*
 * This structure tracks our fundamental unit of work.  Whenever
 * an SRP Information Unit (IU) arrives, we track all the good stuff
 * here
 */
struct iu_entry {
	struct server_adapter *adapter;

	struct list_head ilist;
	dma_addr_t iu_token;

	struct {
		dma_addr_t remote_token;
		char *sense;
		unsigned long flags;
		int data_out_residual_count;
		int data_in_residual_count;
		int timeout;
	} req;
};


static struct workqueue_struct *vtgtd;
static kmem_cache_t *iu_cache;

/*
 * These are fixed for the system and come from the Open Firmware device tree.
 * We just store them here to save getting them every time.
 */
static char system_id[64] = "";
static char partition_name[97] = "UNKNOWN";
static unsigned int partition_number = -1;

static int send_iu(struct iu_entry *iue, uint64_t length, uint8_t format)
{
	long rc, rc1;
	union {
		struct viosrp_crq cooked;
		uint64_t raw[2];
	} crq;

	/* First copy the SRP */
	rc = h_copy_rdma(length, iue->adapter->liobn, iue->iu_token,
			 iue->adapter->riobn, iue->req.remote_token);

	if (rc)
		eprintk("Error %ld transferring data\n", rc);

	crq.cooked.valid = 0x80;
	crq.cooked.format = format;
	crq.cooked.reserved = 0x00;
	crq.cooked.timeout = 0x00;
	crq.cooked.IU_length = length;
	crq.cooked.IU_data_ptr = vio_iu(iue)->srp.generic.tag;

	if (rc == 0)
		crq.cooked.status = 0x99;	/* Just needs to be non-zero */
	else
		crq.cooked.status = 0x00;

	rc1 = h_send_crq(iue->adapter->dma_dev->unit_address,
			 crq.raw[0], crq.raw[1]);

	if (rc1) {
		eprintk("%ld sending response\n", rc1);
		return rc1;
	}

	return rc;
}

static int send_rsp(struct iu_entry *iue, unsigned char status,
		    unsigned char asc)
{
	union viosrp_iu *iu = vio_iu(iue);
	uint8_t *sense = iu->srp.rsp.sense_and_response_data;
	uint64_t tag = iu->srp.generic.tag;
	unsigned long flags;

	/* If the linked bit is on and status is good */
	if (test_bit(V_LINKED, &iue->req.flags) && (status == NO_SENSE))
		status = 0x10;

	memset(iu, 0, sizeof(struct srp_rsp));
	iu->srp.rsp.type = SRP_RSP_TYPE;
	spin_lock_irqsave(&iue->adapter->lock, flags);
	iu->srp.rsp.request_limit_delta = 1 + iue->adapter->next_rsp_delta;
	iue->adapter->next_rsp_delta = 0;
	spin_unlock_irqrestore(&iue->adapter->lock, flags);
	iu->srp.rsp.tag = tag;

	iu->srp.rsp.diover = test_bit(V_DIOVER, &iue->req.flags) ? 1 : 0;

	iu->srp.rsp.data_in_residual_count = iue->req.data_in_residual_count;
	iu->srp.rsp.data_out_residual_count = iue->req.data_out_residual_count;

	iu->srp.rsp.rspvalid = 0;

	iu->srp.rsp.response_data_list_length = 0;

	if (status && !iue->req.sense) {
		iu->srp.rsp.status = SAM_STAT_CHECK_CONDITION;
		iu->srp.rsp.snsvalid = 1;
		iu->srp.rsp.sense_data_list_length = 18;

		/* Valid bit and 'current errors' */
		sense[0] = (0x1 << 7 | 0x70);

		/* Sense key */
		sense[2] = status;

		/* Additional sense length */
		sense[7] = 0xa;	/* 10 bytes */

		/* Additional sense code */
		sense[12] = asc;
	} else {
		if (iue->req.sense) {
			iu->srp.rsp.snsvalid = 1;
			iu->srp.rsp.sense_data_list_length =
							SCSI_SENSE_BUFFERSIZE;
			memcpy(sense, iue->req.sense, SCSI_SENSE_BUFFERSIZE);
		}
		iu->srp.rsp.status = status;
	}

	send_iu(iue, sizeof(iu->srp.rsp), VIOSRP_SRP_FORMAT);

	return 0;
}

static int data_out_desc_size(struct srp_cmd *cmd)
{
	int size = 0;
	switch (cmd->data_out_format) {
	case SRP_NO_BUFFER:
		break;
	case SRP_DIRECT_BUFFER:
		size = sizeof(struct memory_descriptor);
		break;
	case SRP_INDIRECT_BUFFER:
		size = sizeof(struct indirect_descriptor) +
			sizeof(struct memory_descriptor) * (cmd->data_out_count - 1);
		break;
	default:
		eprintk("client error. Invalid data_out_format %d\n",
			cmd->data_out_format);
		break;
	}
	return size;
}

static int vscsis_data_length(struct srp_cmd *cmd, int out)
{
	struct memory_descriptor *md;
	struct indirect_descriptor *id;
	int format, len = 0, offset = cmd->additional_cdb_len * 4;

	if (out)
		format = cmd->data_out_format;
	else {
		format = cmd->data_in_format;
		offset += data_out_desc_size(cmd);
	}

	switch (format) {
	case SRP_NO_BUFFER:
		break;
	case SRP_DIRECT_BUFFER:
		md = (struct memory_descriptor *)
			(cmd->additional_data + offset);
		len = md->length;
		break;
	case SRP_INDIRECT_BUFFER:
		id = (struct indirect_descriptor *)
			(cmd->additional_data + offset);
		len = id->total_length;
		break;
	default:
		eprintk("invalid data format %d\n", format);
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
	struct Scsi_host *shost = iue->adapter->shost;
	union viosrp_iu *iu = vio_iu(iue);
	enum dma_data_direction data_dir;
	struct scsi_cmnd *scmd;
	int tag, len;

	dprintk("%p %p\n", iue->adapter, iue);

	if (getlink(iue))
		__set_bit(V_LINKED, &iue->req.flags);

	tag = MSG_SIMPLE_TAG;

	switch (iu->srp.cmd.task_attribute) {
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
			iu->srp.cmd.task_attribute);
		tag = MSG_ORDERED_TAG;
	}

	switch (iu->srp.cmd.cdb[0]) {
	case WRITE_6:
	case WRITE_10:
	case WRITE_VERIFY:
	case WRITE_12:
	case WRITE_VERIFY_12:
		__set_bit(V_WRITE, &iue->req.flags);
	}

	if (iu->srp.cmd.data_out_format) {
		data_dir = DMA_TO_DEVICE;
		len = vscsis_data_length(&iu->srp.cmd, 1);
	} else {
		data_dir = DMA_FROM_DEVICE;
		len = vscsis_data_length(&iu->srp.cmd, 0);
	}

	dprintk("%p %x %lx %d %d %d %llx\n",
		iue, iu->srp.cmd.cdb[0], iu->srp.cmd.lun, data_dir, len, tag,
		(unsigned long long) iu->srp.cmd.tag);

	scmd = scsi_host_get_command(shost, data_dir, GFP_KERNEL);
	BUG_ON(!scmd);

	scmd->SCp.ptr = (char *) iue;
	memcpy(scmd->data_cmnd, iu->srp.cmd.cdb, MAX_COMMAND_SIZE);
	scmd->request_bufflen = len;
	scmd->tag= tag;
	scsi_tgt_queue_command(scmd, (struct scsi_lun *) &iu->srp.cmd.lun, 0);

	dprintk("%p %p %x %lx %d %d %d\n",
		iue, scmd, iu->srp.cmd.cdb[0], iu->srp.cmd.lun, data_dir, len, tag);

	return 0;
}

static void handle_cmd_queue(struct server_adapter *adapter)
{
	struct iu_entry *iue;
	unsigned long flags;

retry:
	spin_lock_irqsave(&adapter->lock, flags);

	list_for_each_entry(iue, &adapter->cmd_queue, ilist) {
		if (!test_and_set_bit(V_FLYING, &iue->req.flags)) {
			spin_unlock_irqrestore(&adapter->lock, flags);
			process_cmd(iue);
			goto retry;
		}
	}

	spin_unlock_irqrestore(&adapter->lock, flags);
}

#define SEND	0
#define RECV	1

static int direct_data(struct scsi_cmnd *scmd, struct memory_descriptor *md,
		       int op)
{
	struct iu_entry *iue = (struct iu_entry *) scmd->SCp.ptr;
	struct server_adapter *adapter = iue->adapter;
	struct scatterlist *sg = scmd->request_buffer;
	unsigned int rest, len;
	int i, done, nsg;
	long err;
	dma_addr_t token;

	dprintk("%p %u %u %u %d\n", iue, scmd->request_bufflen, scmd->bufflen,
		md->length, scmd->use_sg);

	nsg = dma_map_sg(adapter->dev, sg, scmd->use_sg, DMA_BIDIRECTIONAL);
	if (!nsg) {
		eprintk("fail to map %p %d\n", iue, scmd->use_sg);
		return 0;
	}

	rest = min(scmd->request_bufflen, md->length);

	for (i = 0, done = 0; i < nsg && rest; i++) {
		token = sg_dma_address(sg + i);
		len = min(sg_dma_len(sg + i), rest);

		if (op == SEND)
			err = h_copy_rdma(len, adapter->liobn,
					  token,
					  adapter->riobn,
					  md->virtual_address + done);
		else
			err = h_copy_rdma(len, adapter->riobn,
					  md->virtual_address + done,
					  adapter->liobn,
					  token);

		if (err != H_Success) {
			eprintk("rdma error %d %d %ld\n", op, i, err);
			break;
		}

		rest -= len;
		done += len;
	}

	dma_unmap_sg(adapter->dev, sg, nsg, DMA_BIDIRECTIONAL);

	return done;
}

static int indirect_data(struct scsi_cmnd *scmd, struct indirect_descriptor *id,
			 int op)
{
	struct iu_entry *iue = (struct iu_entry *) scmd->SCp.ptr;
	struct server_adapter *adapter = iue->adapter;
	struct srp_cmd *cmd = &vio_iu(iue)->srp.cmd;
	struct memory_descriptor *mds;
	struct scatterlist *sg = scmd->request_buffer;
	dma_addr_t token, itoken = 0;
	long err;
	unsigned int rest, done = 0;
	int i, nmd, nsg, sidx, soff;

	nmd = id->head.length / sizeof(struct memory_descriptor);

	dprintk("%p %u %u %u %u %d %d %d\n",
		iue, scmd->request_bufflen, scmd->bufflen,
		id->total_length, scmd->offset, nmd,
		cmd->data_in_count, cmd->data_out_count);

	if ((op == SEND && nmd == cmd->data_in_count) ||
	    (op == RECV && nmd == cmd->data_out_count)) {
		mds = &id->list[0];
		goto rdma;
	}

	mds = dma_alloc_coherent(adapter->dev, id->head.length,
				 &itoken, GFP_KERNEL);
	if (!mds) {
		eprintk("Can't get dma memory %d\n", id->head.length);
		return 0;
	}

	err = h_copy_rdma(id->head.length, adapter->riobn,
			  id->head.virtual_address, adapter->liobn, itoken);
	if (err != H_Success) {
		eprintk("Error copying indirect table %ld\n", err);
		goto free_mem;
	}

rdma:
	nsg = dma_map_sg(adapter->dev, sg, scmd->use_sg, DMA_BIDIRECTIONAL);
	if (!nsg) {
		eprintk("fail to map %p %d\n", iue, scmd->use_sg);
		goto free_mem;
	}

	sidx = soff = 0;
	token = sg_dma_address(sg + sidx);
	rest = min(scmd->request_bufflen, id->total_length);
	for (i = 0; i < nmd && rest; i++) {
		unsigned int mdone, mlen;

		mlen = min(rest, mds[i].length);
		for (mdone = 0; mlen;) {
			int slen = min(sg_dma_len(sg + sidx) - soff, mlen);

			if (op == SEND)
				err = h_copy_rdma(slen,
						  adapter->liobn,
						  token + soff,
						  adapter->riobn,
						  mds[i].virtual_address + mdone);
			else
				err = h_copy_rdma(slen,
						  adapter->riobn,
						  mds[i].virtual_address + mdone,
						  adapter->liobn,
						  token + soff);

			if (err != H_Success) {
				eprintk("rdma error %d %d\n", op, slen);
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
	dma_unmap_sg(adapter->dev, sg, nsg, DMA_BIDIRECTIONAL);

free_mem:
	if (itoken)
		dma_free_coherent(adapter->dev, id->head.length, mds, itoken);

	return done;
}

static int handle_cmd_data(struct scsi_cmnd *scmd, int op)
{
	struct iu_entry *iue = (struct iu_entry *) scmd->SCp.ptr;
	struct srp_cmd *cmd = &vio_iu(iue)->srp.cmd;
	struct memory_descriptor *md;
	struct indirect_descriptor *id;
	int offset, err = 0;
	uint8_t format;

	offset = cmd->additional_cdb_len * 4;
	if (op == SEND)
		offset += data_out_desc_size(cmd);

	format = (op == SEND) ? cmd->data_in_format : cmd->data_out_format;

	switch (format) {
	case SRP_NO_BUFFER:
		break;
	case SRP_DIRECT_BUFFER:
		md = (struct memory_descriptor *)
			(cmd->additional_data + offset);
		err = direct_data(scmd, md, op);
		break;
	case SRP_INDIRECT_BUFFER:
		id = (struct indirect_descriptor *)
			(cmd->additional_data + offset);
		err = indirect_data(scmd, id, op);
		break;
	default:
		eprintk("Unknown format %d %d\n", op, format);
		break;
	}

	return err;
}

/* TODO: this can be called multiple times for a single command. */
static int recv_cmd_data(struct scsi_cmnd *scmd,
			 void (*done)(struct scsi_cmnd *))
{
	struct iu_entry	*iue = (struct iu_entry *) scmd->SCp.ptr;
	int rw;

	rw = test_bit(V_WRITE, &iue->req.flags) ? RECV : SEND;
	handle_cmd_data(scmd, rw);
	done(scmd);
	return 0;
}

static struct iu_entry *get_iu(struct server_adapter *adapter)
{
	struct iu_entry *iue;

	iue = mempool_alloc(adapter->iu_pool, GFP_ATOMIC);
	if (!iue)
		return NULL;

	memset(&iue->req, 0, sizeof(iue->req));
	iue->adapter = adapter;
	INIT_LIST_HEAD(&iue->ilist);

	iue->iu_token = dma_map_single(adapter->dev, vio_iu(iue),
				       sizeof(union viosrp_iu),
				       DMA_BIDIRECTIONAL);
	if (dma_mapping_error(iue->iu_token)) {
		mempool_free(iue, adapter->iu_pool);
		iue = NULL;
	}

	return iue;
}

static void put_iu(struct iu_entry *iue)
{
	struct server_adapter *adapter = iue->adapter;

	dprintk("%p %p\n", adapter, iue);

	dma_unmap_single(adapter->dev, iue->iu_token,
			 sizeof(union viosrp_iu), DMA_BIDIRECTIONAL);
	mempool_free(iue, adapter->iu_pool);
}

static int ibmvstgt_cmd_done(struct scsi_cmnd *scmd,
			     void (*done)(struct scsi_cmnd *))
{
	unsigned long flags;
	struct iu_entry *iue = (struct iu_entry *) scmd->SCp.ptr;
	struct server_adapter *adapter = iue->adapter;

	dprintk("%p %p %x\n", iue, adapter, vio_iu(iue)->srp.cmd.cdb[0]);

	spin_lock_irqsave(&adapter->lock, flags);
	list_del(&iue->ilist);
	spin_unlock_irqrestore(&adapter->lock, flags);

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
	struct server_adapter *adapter = iue->adapter;
	struct Scsi_Host *shost = adapter->shost;
	dma_addr_t data_token;
	struct mad_adapter_info_data *info;
	int err;

	info = dma_alloc_coherent(adapter->dev, sizeof(*info),
				  &data_token, GFP_KERNEL);

	if (!info) {
		eprintk("bad dma_alloc_coherent %p\n", adapter);
		return 1;
	}

	/* Get remote info */
	err = h_copy_rdma(sizeof(*info), adapter->riobn, remote_buffer,
			  adapter->liobn, data_token);
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
	err = h_copy_rdma(sizeof(*info), adapter->liobn, data_token,
			  adapter->riobn, remote_buffer);

	dma_free_coherent(adapter->dev, sizeof(*info), info,
			  data_token);

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

	uint64_t tag = iu->srp.generic.tag;

	/* TODO handle case that requested size is wrong and
	 * buffer format is wrong
	 */
	memset(iu, 0, sizeof(struct srp_login_rsp));
	rsp->type = SRP_LOGIN_RSP_TYPE;
	rsp->request_limit_delta = INITIAL_SRP_LIMIT;
	rsp->tag = tag;
	rsp->max_initiator_to_target_iulen = sizeof(union srp_iu);
	rsp->max_target_to_initiator_iulen = sizeof(union srp_iu);
	/* direct and indirect */
	rsp->supported_buffer_formats = 0x0006;
	rsp->multi_channel_result = 0x00;

	send_iu(iue, sizeof(*rsp), VIOSRP_SRP_FORMAT);
}

static inline void queue_cmd(struct iu_entry *iue)
{
	struct server_adapter *adapter = iue->adapter;
	unsigned long flags;

	spin_lock_irqsave(&adapter->lock, flags);
	list_add_tail(&iue->ilist, &iue->adapter->cmd_queue);
	spin_unlock_irqrestore(&adapter->lock, flags);
	handle_cmd_queue(adapter);
}

/* TODO */
static void process_device_reset(struct iu_entry *iue)
{
	send_rsp(iue, NO_SENSE, 0x00);
}

static void process_abort(struct iu_entry *iue)
{
	union viosrp_iu *iu = vio_iu(iue), *tmp_iu = NULL;
	struct iu_entry *tmp_iue;
	unsigned char status = ABORTED_COMMAND;
	uint64_t tag = iu->srp.tsk_mgmt.managed_task_tag;
	unsigned long flags;

	eprintk("Not supported yet %p %llx\n", iue, (unsigned long long) tag);

	spin_lock_irqsave(&iue->adapter->lock, flags);

	list_for_each_entry(tmp_iue, &iue->adapter->cmd_queue, ilist) {
		tmp_iu = vio_iu(tmp_iue);
		if (tmp_iu->srp.cmd.tag != tag)
			continue;

		__set_bit(V_ABORTED, &tmp_iue->req.flags);
		status = NO_SENSE;
		break;
	}

	spin_unlock_irqrestore(&iue->adapter->lock, flags);

	if (status == NO_SENSE) {
		int len = vscsis_data_length(&tmp_iu->srp.cmd,
					     tmp_iu->srp.cmd.data_out_format);
		dprintk("%p %x %lx %d\n",
			tmp_iue, tmp_iu->srp.cmd.cdb[0], tmp_iu->srp.cmd.lun, len);
		dprintk("abort successful\n");
		BUG();
	} else
		dprintk("unable to abort cmd\n");

	send_rsp(iue, status, 0x14);
}

static void process_tsk_mgmt(struct iu_entry *iue)
{
	union viosrp_iu *iu = vio_iu(iue);
	uint8_t flags = iu->srp.tsk_mgmt.task_mgmt_flags;

	if (flags == 0x01)
		process_abort(iue);
	else if (flags == 0x08)
		process_device_reset(iue);
	else
		send_rsp(iue, ILLEGAL_REQUEST, 0x20);
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
		eprintk("Unknown type %d\n", iu->srp.generic.type);
	}

	return 1;
}

static int process_srp_iu(struct iu_entry *iue)
{
	union viosrp_iu *iu = vio_iu(iue);
	int done = 1;

	dprintk("%p %d\n", iue, iu->srp.generic.type);

	switch (iu->srp.generic.type) {
	case SRP_LOGIN_REQ_TYPE:
		process_login(iue);
		break;
	case SRP_TSK_MGMT_TYPE:
		process_tsk_mgmt(iue);
		break;
	case SRP_CMD_TYPE:
		queue_cmd(iue);
		done = 0;
		break;
	case SRP_LOGIN_RSP_TYPE:
	case SRP_I_LOGOUT_TYPE:
	case SRP_T_LOGOUT_TYPE:
	case SRP_RSP_TYPE:
	case SRP_CRED_REQ_TYPE:
	case SRP_CRED_RSP_TYPE:
	case SRP_AER_REQ_TYPE:
	case SRP_AER_RSP_TYPE:
		eprintk("Unsupported type %d\n", iu->srp.generic.type);
		break;
	default:
		eprintk("Unknown type %d\n", iu->srp.generic.type);
	}

	return done;
}

static void process_iu(struct viosrp_crq *crq, struct server_adapter *adapter)
{
	struct iu_entry *iue;
	long err, done;

	iue = get_iu(adapter);
	if (!iue) {
		eprintk("Error getting IU from pool, %p\n", adapter);
		return;
	}

	dprintk("%p %p\n", adapter, iue);

	iue->req.remote_token = crq->IU_data_ptr;
	iue->req.timeout= crq->timeout ? crq->timeout * HZ : DEFAULT_TIMEOUT;

	err = h_copy_rdma(crq->IU_length, iue->adapter->riobn,
			  iue->req.remote_token, adapter->liobn, iue->iu_token);

	if (err != H_Success)
		eprintk("%ld transferring data error %p\n", err, iue);

	if (crq->format == VIOSRP_MAD_FORMAT)
		done = process_mad_iu(iue);
	else
		done = process_srp_iu(iue);

	if (done)
		put_iu(iue);
}

static irqreturn_t ibmvstgt_interrupt(int irq, void *dev_instance,
				      struct pt_regs *regs)
{
	struct server_adapter *adapter = (struct server_adapter *)dev_instance;

	vio_disable_interrupts(adapter->dma_dev);
	queue_work(vtgtd, &adapter->crq_work);

	return IRQ_HANDLED;
}

static int crq_queue_create(struct crq_queue *queue,
			    struct server_adapter *adapter)
{
	int err;

	queue->msgs = (struct viosrp_crq *) get_zeroed_page(GFP_KERNEL);
	if (!queue->msgs)
		goto malloc_failed;
	queue->size = PAGE_SIZE / sizeof(*queue->msgs);

	queue->msg_token = dma_map_single(adapter->dev, queue->msgs,
					  queue->size * sizeof(*queue->msgs),
					  DMA_BIDIRECTIONAL);

	if (dma_mapping_error(queue->msg_token))
		goto map_failed;

	err = h_reg_crq(adapter->dma_dev->unit_address, queue->msg_token,
			PAGE_SIZE);

	/* If the adapter was left active for some reason (like kexec)
	 * try freeing and re-registering
	 */
	if (err == H_Resource) {
	    do {
		err = h_free_crq(adapter->dma_dev->unit_address);
	    } while (err == H_Busy || H_isLongBusy(err));

	    err = h_reg_crq(adapter->dma_dev->unit_address, queue->msg_token,
			    PAGE_SIZE);
	}

	if (err != H_Success && err != 2) {
		eprintk("Error 0x%x opening virtual adapter\n", err);
		goto reg_crq_failed;
	}

	err = request_irq(adapter->dma_dev->irq, &ibmvstgt_interrupt,
			  SA_INTERRUPT, "ibmvstgt", adapter);
	if (err)
		goto req_irq_failed;

	vio_enable_interrupts(adapter->dma_dev);

	h_send_crq(adapter->dma_dev->unit_address, 0xC001000000000000, 0);

	queue->cur = 0;
	spin_lock_init(&queue->lock);

	return 0;

req_irq_failed:
	do {
		err = h_free_crq(adapter->dma_dev->unit_address);
	} while (err == H_Busy || H_isLongBusy(err));

reg_crq_failed:
	dma_unmap_single(adapter->dev, queue->msg_token,
			 queue->size * sizeof(*queue->msgs), DMA_BIDIRECTIONAL);
map_failed:
	free_page((unsigned long) queue->msgs);

malloc_failed:
	return -ENOMEM;
}

static void crq_queue_destroy(struct server_adapter *adapter)
{
	struct crq_queue *queue = &adapter->crq_queue;
	int err;

	free_irq(adapter->dma_dev->irq, adapter);
	do {
		err = h_free_crq(adapter->dma_dev->unit_address);
	} while (err == H_Busy || H_isLongBusy(err));

	dma_unmap_single(adapter->dev, queue->msg_token,
			 queue->size * sizeof(*queue->msgs), DMA_BIDIRECTIONAL);

	free_page((unsigned long) queue->msgs);
}

static void process_crq(struct viosrp_crq *crq,
			struct server_adapter *adapter)
{
	dprintk("%x %x\n", crq->valid, crq->format);

	switch (crq->valid) {
	case 0xC0:
		/* initialization */
		switch (crq->format) {
		case 0x01:
			h_send_crq(adapter->dma_dev->unit_address,
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
			process_iu(crq, adapter);
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
	struct server_adapter *adapter = (struct server_adapter *) data;
	struct viosrp_crq *crq;
	int done = 0;

	while (!done) {
		while ((crq = next_crq(&adapter->crq_queue)) != NULL) {
			process_crq(crq, adapter);
			crq->valid = 0x00;
		}

		vio_enable_interrupts(adapter->dma_dev);

		crq = next_crq(&adapter->crq_queue);
		if (crq) {
			vio_disable_interrupts(adapter->dma_dev);
			process_crq(crq, adapter);
			crq->valid = 0x00;
		} else
			done = 1;
	}

	handle_cmd_queue(adapter);
}

/*
 * TODO: just for cheating scsi_host_alloc now.
 */
static int ibmvstgt_eh_abort_handler(struct scsi_cmnd *cmd)
{
	BUG();
	return 0;
}

#define	host_to_adapter(x)	(((struct server_adapter *) x->hostdata))

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
	struct server_adapter *adapter = host_to_adapter(shost);
	return snprintf(buf, PAGE_SIZE, "%x\n", adapter->dma_dev->unit_address);
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
	.shost_attrs		= ibmvstgt_attrs,
	.proc_name		= TGT_NAME,
};

static int ibmvstgt_probe(struct vio_dev *dev, const struct vio_device_id *id)
{
	struct Scsi_Host *shost;
	struct server_adapter *adapter;
	unsigned int *dma, dma_size;
	int err = -ENOMEM;

	dprintk("%s %s %x %u\n", dev->name, dev->type,
		dev->unit_address, dev->irq);

	shost = scsi_host_alloc(&ibmvstgt_sht, sizeof(struct server_adapter));
	if (!shost)
		return err;
	if (scsi_tgt_alloc_queue(shost))
		goto put_host;

	adapter = (struct server_adapter *) shost->hostdata;
	adapter->shost = shost;
	adapter->dma_dev = dev;
	adapter->dev = &dev->dev;
	adapter->dev->driver_data = adapter;
	adapter->next_rsp_delta = 0;
	spin_lock_init(&adapter->lock);

	dma = (unsigned int *)
		vio_get_attribute(dev, "ibm,my-dma-window", &dma_size);
	if (!dma || dma_size != 40) {
		eprintk("Couldn't get window property %d\n", dma_size);
		err = -EIO;
		goto put_host;
	}

	adapter->liobn = dma[0];
	adapter->riobn = dma[5];

	INIT_WORK(&adapter->crq_work, handle_crq, adapter);
	INIT_LIST_HEAD(&adapter->cmd_queue);

	adapter->iu_pool = mempool_create(INITIAL_SRP_LIMIT,
					  mempool_alloc_slab,
					  mempool_free_slab, iu_cache);
	if (!adapter->iu_pool)
		goto put_host;

	err = crq_queue_create(&adapter->crq_queue, adapter);
	if (err)
		goto free_pool;

	if (scsi_add_host(shost, adapter->dev))
		goto destroy_queue;
	return 0;

destroy_queue:
	crq_queue_destroy(adapter);
free_pool:
	mempool_destroy(adapter->iu_pool);
put_host:
	scsi_host_put(shost);

	return err;
}

static int ibmvstgt_remove(struct vio_dev *dev)
{
	struct server_adapter *adapter =
		(struct server_adapter *) dev->dev.driver_data;
	struct Scsi_Host *shost = adapter->shost;

	scsi_remove_host(shost);
	scsi_host_put(shost);
	crq_queue_destroy(adapter);
	mempool_destroy(adapter->iu_pool);

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
	size_t size = sizeof(struct iu_entry) + sizeof(union viosrp_iu);

	printk("IBM eServer i/pSeries Virtual SCSI Target Driver\n");

	iu_cache = kmem_cache_create("ibmvstgt_iu",
				     size, 0,
				     SLAB_HWCACHE_ALIGN | SLAB_NO_REAP,
				     NULL, NULL);
	if (!iu_cache)
		return err;

	vtgtd = create_workqueue("ibmvtgtd");
	if (!vtgtd)
		goto free_iu_cache;

	err = get_system_info();
	if (err < 0)
		goto destroy_wq;

	err = vio_register_driver(&ibmvstgt_driver);
	if (err)
		goto destroy_wq;

	return 0;

destroy_wq:
	destroy_workqueue(vtgtd);
free_iu_cache:
	kmem_cache_destroy(iu_cache);

	return err;
}

static void ibmvstgt_exit(void)
{
	printk("Unregister IBM virtual SCSI driver\n");

	destroy_workqueue(vtgtd);
	vio_unregister_driver(&ibmvstgt_driver);
	kmem_cache_destroy(iu_cache);
}

module_init(ibmvstgt_init);
module_exit(ibmvstgt_exit);
