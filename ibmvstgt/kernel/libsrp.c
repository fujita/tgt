/*
 * SCSI RDAM Protocol lib functions
 *
 * Copyright (C) 2006 FUJITA Tomonori <tomof@acm.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */
#include <linux/err.h>
#include <linux/kfifo.h>
#include <linux/scatterlist.h>
#include <linux/dma-mapping.h>
#include <scsi/scsi.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_tcq.h>
#include <scsi/scsi_tgt.h>
#include <scsi/srp.h>
#include <libsrp.h>

enum srp_task_attributes {
	SRP_SIMPLE_TASK = 0,
	SRP_HEAD_TASK = 1,
	SRP_ORDERED_TASK = 2,
	SRP_ACA_TASK = 4
};

/* tmp - will replace with SCSI logging stuff */
#define eprintk(fmt, args...)					\
do {								\
	printk("%s(%d) " fmt, __FUNCTION__, __LINE__, ##args);	\
} while (0)
/* #define dprintk eprintk */
#define dprintk(fmt, args...)

static int srp_iu_pool_alloc(struct srp_queue *q, size_t max,
			     struct srp_buf **ring)
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

static void srp_iu_pool_free(struct srp_queue *q)
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

int srp_target_alloc(struct srp_target *target, struct device *dev,
		     size_t nr, size_t iu_size)
{
	int err;

	spin_lock_init(&target->lock);
	INIT_LIST_HEAD(&target->cmd_queue);

	target->dev = dev;
	target->dev->driver_data = target;

	target->srp_iu_size = iu_size;
	target->rx_ring_size = nr;
	target->rx_ring = srp_ring_alloc(target->dev, nr, iu_size);
	if (!target->rx_ring)
		return -ENOMEM;
	err = srp_iu_pool_alloc(&target->iu_queue, nr, target->rx_ring);
	if (err)
		goto free_ring;

	return 0;

free_ring:
	srp_ring_free(target->dev, target->rx_ring, nr, iu_size);
	return -ENOMEM;
}
EXPORT_SYMBOL_GPL(srp_target_alloc);

void srp_target_free(struct srp_target *target)
{
	srp_ring_free(target->dev, target->rx_ring, target->rx_ring_size,
		      target->srp_iu_size);
	srp_iu_pool_free(&target->iu_queue);
}
EXPORT_SYMBOL_GPL(srp_target_free);

struct iu_entry *srp_iu_get(struct srp_target *target)
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
EXPORT_SYMBOL_GPL(srp_iu_get);

void srp_iu_put(struct iu_entry *iue)
{
	kfifo_put(iue->target->iu_queue.queue, (void *) &iue, sizeof(void *));
}
EXPORT_SYMBOL_GPL(srp_iu_put);

static int direct_data(struct scsi_cmnd *scmd, struct srp_direct_buf *md,
		       enum dma_data_direction dir, rdma_io_t rdma_io)
{
	struct iu_entry *iue = (struct iu_entry *) scmd->SCp.ptr;
	struct srp_target *target = iue->target;
	struct scatterlist *sg = scmd->request_buffer;
	int nsg, err;

	dprintk("%p %u %u %u %d\n", iue, scmd->request_bufflen, scmd->bufflen,
		md->len, scmd->use_sg);

	nsg = dma_map_sg(target->dev, sg, scmd->use_sg, DMA_BIDIRECTIONAL);
	if (!nsg) {
		printk("fail to map %p %d\n", iue, scmd->use_sg);
		return 0;
	}
	err = rdma_io(iue, sg, nsg, md, 1, dir,
		      min(scmd->request_bufflen, md->len));

	dma_unmap_sg(target->dev, sg, nsg, DMA_BIDIRECTIONAL);

	return err;
}

static int indirect_data(struct scsi_cmnd *scmd, struct srp_cmd *cmd,
			 struct srp_indirect_buf *id,
			 enum dma_data_direction dir, rdma_io_t rdma_io)
{
	struct iu_entry *iue = (struct iu_entry *) scmd->SCp.ptr;
	struct srp_target *target = iue->target;
	struct srp_direct_buf *md;
	struct scatterlist dummy, *sg = scmd->request_buffer;
	dma_addr_t token = 0;
	long err;
	unsigned int done = 0;
	int nmd, nsg;

	nmd = id->table_desc.len / sizeof(struct srp_direct_buf);

	dprintk("%p %u %u %u %u %d %d %d\n",
		iue, scmd->request_bufflen, scmd->bufflen,
		id->len, scmd->offset, nmd,
		cmd->data_in_desc_cnt, cmd->data_out_desc_cnt);

	if ((dir == DMA_FROM_DEVICE && nmd == cmd->data_in_desc_cnt) ||
	    (dir == DMA_TO_DEVICE && nmd == cmd->data_out_desc_cnt)) {
		md = &id->desc_list[0];
		goto rdma;
	}

	md = dma_alloc_coherent(target->dev, id->table_desc.len,
				 &token, GFP_KERNEL);
	if (!md) {
		eprintk("Can't get dma memory %u\n", id->table_desc.len);
		return 0;
	}

	sg_init_one(&dummy, md, id->table_desc.len);
	sg_dma_address(&dummy) = token;
	err = rdma_io(iue, &dummy, 1, &id->table_desc, 1, DMA_TO_DEVICE,
		      id->table_desc.len);
	if (err < 0) {
		eprintk("Error copying indirect table %ld\n", err);
		goto free_mem;
	}

rdma:
	nsg = dma_map_sg(target->dev, sg, scmd->use_sg, DMA_BIDIRECTIONAL);
	if (!nsg) {
		eprintk("fail to map %p %d\n", iue, scmd->use_sg);
		goto free_mem;
	}

	err = rdma_io(iue, sg, nsg, md, nmd, dir,
		      min(scmd->request_bufflen, id->len));
	dma_unmap_sg(target->dev, sg, nsg, DMA_BIDIRECTIONAL);

free_mem:
	if (token)
		dma_free_coherent(target->dev, id->table_desc.len, md, token);

	return done;
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

static int __srp_transfer_data(struct scsi_cmnd *scmd, struct srp_cmd *cmd,
			       enum dma_data_direction dir, rdma_io_t rdma_io)
{
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
		err = direct_data(scmd, md, dir, rdma_io);
		break;
	case SRP_DATA_DESC_INDIRECT:
		id = (struct srp_indirect_buf *)
			(cmd->add_data + offset);
		err = indirect_data(scmd, cmd, id, dir, rdma_io);
		break;
	default:
		eprintk("Unknown format %d %x\n", dir, format);
		break;
	}

	return err;
}

/* TODO: this can be called multiple times for a single command. */
int srp_transfer_data(struct scsi_cmnd *scmd, struct srp_cmd *cmd,
		      rdma_io_t rdma_io)
{
	struct iu_entry	*iue = (struct iu_entry *) scmd->SCp.ptr;
	enum dma_data_direction dir;

	if (test_bit(V_WRITE, &iue->flags))
		dir = DMA_TO_DEVICE;
	else
		dir = DMA_FROM_DEVICE;
	__srp_transfer_data(scmd, cmd, dir, rdma_io);
	return 0;
}
EXPORT_SYMBOL_GPL(srp_transfer_data);

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

static u8 getcontrolbyte(u8 *cdb)
{
	return cdb[COMMAND_SIZE(cdb[0]) - 1];
}

static inline u8 getlink(struct srp_cmd *cmd)
{
	return (getcontrolbyte(cmd->cdb) & 0x01);
}

int srp_cmd_perform(struct iu_entry *iue, struct srp_cmd *cmd)
{
	struct Scsi_Host *shost = iue->target->shost;
	enum dma_data_direction data_dir;
	struct scsi_cmnd *scmd;
	int tag, len;

	if (getlink(cmd))
		__set_bit(V_LINKED, &iue->flags);

	tag = MSG_SIMPLE_TAG;

	switch (cmd->task_attr) {
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
		eprintk("Task attribute %d not supported\n", cmd->task_attr);
		tag = MSG_ORDERED_TAG;
	}

	switch (cmd->cdb[0]) {
	case WRITE_6:
	case WRITE_10:
	case WRITE_VERIFY:
	case WRITE_12:
	case WRITE_VERIFY_12:
		__set_bit(V_WRITE, &iue->flags);
	}

	if (cmd->buf_fmt >> 4)
		data_dir = DMA_TO_DEVICE;
	else
		data_dir = DMA_FROM_DEVICE;
	len = vscsis_data_length(cmd, data_dir);

	dprintk("%p %x %lx %d %d %d %llx\n", iue, cmd->cdb[0],
		cmd->lun, data_dir, len, tag, (unsigned long long) cmd->tag);

	scmd = scsi_host_get_command(shost, data_dir, GFP_KERNEL);
	BUG_ON(!scmd);
	scmd->SCp.ptr = (char *) iue;
	memcpy(scmd->data_cmnd, cmd->cdb, MAX_COMMAND_SIZE);
	scmd->request_bufflen = len;
	scmd->tag = tag;
	iue->scmd = scmd;
	scsi_tgt_queue_command(scmd, (struct scsi_lun *) &cmd->lun, cmd->tag);

	return 0;
}
EXPORT_SYMBOL_GPL(srp_cmd_perform);

MODULE_DESCRIPTION("SCSI RDAM Protocol lib functions");
MODULE_AUTHOR("FUJITA Tomonori");
MODULE_LICENSE("GPL");
