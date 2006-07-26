/*
 * SCSI target kernel/user interface functions
 *
 * Copyright (C) 2005 FUJITA Tomonori <tomof@acm.org>
 * Copyright (C) 2005 Mike Christie <michaelc@cs.wisc.edu>
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
#include <linux/blkdev.h>
#include <linux/file.h>
#include <net/tcp.h>
#include <scsi/scsi.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_tgt.h>
#include <scsi/scsi_tgt_if.h>

#include "scsi_tgt_priv.h"

struct rbuf {
	u32 idx;
	u32 nr_entry;
	int entry_size;
	char *buf;
	int buf_size;
	spinlock_t lock;
};

static int chrdev;
static struct rbuf txbuf, rxbuf;
static DECLARE_WAIT_QUEUE_HEAD(tgt_poll_wait);

static inline struct rbuf_hdr *head_rbuf_hdr(struct rbuf *rbuf, u32 idx)
{
	u32 offset = (idx & (rbuf->nr_entry - 1)) * rbuf->entry_size;
	return (struct rbuf_hdr *) (rbuf->buf + offset);
}

static void rbuf_init(struct rbuf *rbuf, char *buf, int bsize, int esize)
{
	int i;

	esize += sizeof(struct rbuf_hdr);
	rbuf->idx = 0;
	rbuf->entry_size = esize;
	rbuf->buf = buf;
	spin_lock_init(&rbuf->lock);

	bsize /= esize;
	for (i = 0; (1 << i) < bsize && (1 << (i + 1)) <= bsize; i++)
		;
	rbuf->nr_entry = 1 << i;
}

static int send_event_rsp(u32 type, struct tgt_event *p)
{
	struct tgt_event *ev;
	struct rbuf_hdr *hdr;
	struct page *sp, *ep;
	unsigned long flags;
	int err = 0;

	spin_lock_irqsave(&txbuf.lock, flags);

	hdr = head_rbuf_hdr(&txbuf, txbuf.idx);
	if (hdr->status)
		err = 1;
	else
		txbuf.idx++;

	spin_unlock_irqrestore(&txbuf.lock, flags);

	if (err)
		return err;

	ev = (struct tgt_event *) hdr->data;
	memcpy(ev, p, sizeof(*ev));
	ev->type = type;
	hdr->status = 1;
	mb();

	sp = virt_to_page(hdr);
	ep = virt_to_page((char *) hdr->data + sizeof(*ev));
	for (;sp <= ep; sp++)
		flush_dcache_page(sp);

	wake_up_interruptible(&tgt_poll_wait);

	return 0;
}

int scsi_tgt_uspace_send_cmd(struct scsi_cmnd *cmd, struct scsi_lun *lun, u64 tag)
{
	struct Scsi_Host *shost = scsi_tgt_cmd_to_host(cmd);
	struct tgt_event ev;
	int err;

	memset(&ev, 0, sizeof(ev));
	ev.k.cmd_req.host_no = shost->host_no;
	ev.k.cmd_req.cid = cmd->request->tag;
	ev.k.cmd_req.data_len = cmd->request_bufflen;
	memcpy(ev.k.cmd_req.scb, cmd->cmnd, sizeof(ev.k.cmd_req.scb));
	memcpy(ev.k.cmd_req.lun, lun, sizeof(ev.k.cmd_req.lun));
	ev.k.cmd_req.attribute = cmd->tag;
	ev.k.cmd_req.tag = tag;

	dprintk("%p %d %u %u %x %llx\n", cmd, shost->host_no, ev.k.cmd_req.cid,
		ev.k.cmd_req.data_len, cmd->tag,
		(unsigned long long) ev.k.cmd_req.tag);

	err = send_event_rsp(TGT_KEVENT_CMD_REQ, &ev);
	if (err)
		eprintk("tx buf is full, could not send\n");
	return err;
}

int scsi_tgt_uspace_send_status(struct scsi_cmnd *cmd)
{
	struct Scsi_Host *shost = scsi_tgt_cmd_to_host(cmd);
	struct tgt_event ev;
	int err;

	memset(&ev, 0, sizeof(ev));
	ev.k.cmd_done.host_no = shost->host_no;
	ev.k.cmd_done.cid = cmd->request->tag;
	ev.k.cmd_done.result = cmd->result;

	dprintk("%p %d %u %u %x %llx\n", cmd, shost->host_no, ev.k.cmd_req.cid,
		ev.k.cmd_req.data_len, cmd->tag,
		(unsigned long long) ev.k.cmd_req.tag);

	err = send_event_rsp(TGT_KEVENT_CMD_DONE, &ev);
	if (err)
		eprintk("tx buf is full, could not send\n");
	return err;
}

int scsi_tgt_uspace_send_tsk_mgmt(int host_no, int function, u64 tag,
				  struct scsi_lun *scsilun, void *data)
{
	struct tgt_event ev;
	int err;

	memset(&ev, 0, sizeof(ev));
	ev.k.tsk_mgmt_req.host_no = host_no;
	ev.k.tsk_mgmt_req.function = function;
	ev.k.tsk_mgmt_req.tag = tag;
	memcpy(ev.k.tsk_mgmt_req.lun, scsilun, sizeof(ev.k.tsk_mgmt_req.lun));
	ev.k.tsk_mgmt_req.mid = (u64) (unsigned long) data;

	dprintk("%d %x %llx %llx\n", host_no, function, (unsigned long long) tag,
		(unsigned long long) ev.k.tsk_mgmt_req.mid);

	err = send_event_rsp(TGT_KEVENT_TSK_MGMT_REQ, &ev);
	if (err)
		eprintk("tx buf is full, could not send\n");
	return err;
}

static int event_recv_msg(struct tgt_event *ev)
{
	int err = 0;

	switch (ev->type) {
	case TGT_UEVENT_CMD_RSP:
		err = scsi_tgt_kspace_exec(ev->u.cmd_rsp.host_no,
					   ev->u.cmd_rsp.cid,
					   ev->u.cmd_rsp.result,
					   ev->u.cmd_rsp.len,
					   ev->u.cmd_rsp.uaddr,
					   ev->u.cmd_rsp.rw);
		break;
	case TGT_UEVENT_TSK_MGMT_RSP:
		err = scsi_tgt_kspace_tsk_mgmt(ev->u.tsk_mgmt_rsp.host_no,
					       ev->u.tsk_mgmt_rsp.mid,
					       ev->u.tsk_mgmt_rsp.result);
		break;
	default:
		eprintk("unknown type %d\n", ev->type);
		err = -EINVAL;
	}

	return err;
}

static ssize_t tgt_write(struct file *file, const char __user * buffer,
			 size_t count, loff_t * ppos)
{
	struct rbuf_hdr *hdr;
	struct tgt_event *ev;
	struct page *sp, *ep;

retry:
	hdr = head_rbuf_hdr(&rxbuf, rxbuf.idx);

	sp = virt_to_page(hdr);
	ep = virt_to_page((char *) hdr->data + sizeof(*ev));
	for (;sp <= ep; sp++)
		flush_dcache_page(sp);

	if (!hdr->status)
		return count;

	rxbuf.idx++;
	ev = (struct tgt_event *) hdr->data;
	event_recv_msg(ev);
	hdr->status = 0;

	goto retry;
}

static unsigned int tgt_poll(struct file * file, struct poll_table_struct *wait)
{
	struct rbuf_hdr *hdr;
	unsigned long flags;
	unsigned int mask = 0;

	poll_wait(file, &tgt_poll_wait, wait);

	spin_lock_irqsave(&txbuf.lock, flags);

	hdr = head_rbuf_hdr(&txbuf, txbuf.idx - 1);
	if (hdr->status)
		mask |= POLLIN | POLLRDNORM;

	spin_unlock_irqrestore(&txbuf.lock, flags);

	return mask;
}

static int tgt_mmap(struct file *filp, struct vm_area_struct *vma)
{
	unsigned long size, addr;
	struct page *page;
	int err, i;

	if (vma->vm_pgoff) {
		eprintk("bug\n");
		return -EINVAL;
	}

	size = vma->vm_end - vma->vm_start;
	if (size != TGT_RINGBUF_SIZE * 2) {
		eprintk("%lu\n", size);
		return -EINVAL;
	}
	addr = vma->vm_start;
	page = virt_to_page(txbuf.buf);
	for (i = 0; i < size >> PAGE_SHIFT; i++) {
		err = vm_insert_page(vma, addr, page);
		if (err) {
			eprintk("%d %d %lu\n", err, i, addr);
			return -EINVAL;
		}
		addr += PAGE_SIZE;
		page++;
	}

	return 0;
}

static struct file_operations tgt_fops = {
	.owner	= THIS_MODULE,
	.poll	= tgt_poll,
	.write	= tgt_write,
	.mmap	= tgt_mmap,
};

void __exit scsi_tgt_if_exit(void)
{
	int order = long_log2(TGT_RINGBUF_SIZE * 2);

	unregister_chrdev(chrdev, "tgt");
	free_pages((unsigned long) txbuf.buf, order);
}

int __init scsi_tgt_if_init(void)
{
	u32 bsize = TGT_RINGBUF_SIZE;
	int order;
	char *buf;

	chrdev = register_chrdev(0, "tgt", &tgt_fops);
	if (chrdev < 0)
		return chrdev;

	order = long_log2((bsize * 2) >> PAGE_SHIFT);
	buf = (char *) __get_free_pages(GFP_KERNEL | __GFP_COMP | __GFP_ZERO,
					order);
	if (!buf)
		goto free_dev;
	rbuf_init(&txbuf, buf, bsize, sizeof(struct tgt_event));
	rbuf_init(&rxbuf, buf + bsize, bsize, sizeof(struct tgt_event));

	return 0;

free_dev:
	unregister_chrdev(chrdev, "tgt");

	return -ENOMEM;
}
