/*
 * SCSI kernel and user interface
 *
 * Copyright (C) 2006-2007 FUJITA Tomonori <tomof@acm.org>
 * Copyright (C) 2006-2007 Mike Christie <michaelc@cs.wisc.edu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <linux/types.h>
#ifndef aligned_u64
#define aligned_u64 uint64_t __attribute__((aligned(8)))
#endif
#include <scsi/scsi_tgt_if.h>

#include "list.h"
#include "util.h"
#include "tgtd.h"

#define barrier() __asm__ __volatile__("": : :"memory")

struct uring {
	uint32_t idx;
	char *buf;
};

static struct uring kuring, ukring;
static int chrfd;

static unsigned long tgt_ring_pages, tgt_max_events, tgt_event_per_page;

static inline void ring_index_inc(struct uring *ring)
{
	ring->idx = (ring->idx == tgt_max_events - 1) ? 0 : ring->idx + 1;
}

static inline struct tgt_event *head_ring_hdr(struct uring *ring)
{
	uint32_t pidx, off, pos;

	pidx = ring->idx / tgt_event_per_page;
	off = ring->idx % tgt_event_per_page;
	pos = pidx * pagesize + off * sizeof(struct tgt_event);

	return (struct tgt_event *) (ring->buf + pos);
}

static int kreq_send(struct tgt_event *p)
{
	struct tgt_event *ev;

	ev = head_ring_hdr(&ukring);
	if (ev->hdr.status)
		return -ENOMEM;

	ring_index_inc(&ukring);

	memcpy(ev, p, sizeof(*p));
	barrier();
	ev->hdr.status = 1;
	write(chrfd, ev, 1);

	return 0;
}

int kspace_send_tsk_mgmt_res(struct mgmt_req *mreq)
{
	struct tgt_event ev;

	memset(&ev, 0, sizeof(ev));

	ev.hdr.type = TGT_UEVENT_TSK_MGMT_RSP;
	ev.p.tsk_mgmt_rsp.host_no = mreq->host_no;
	ev.p.tsk_mgmt_rsp.itn_id = mreq->itn_id;
	ev.p.tsk_mgmt_rsp.mid = mreq->mid;
	ev.p.tsk_mgmt_rsp.result = mreq->result;

	return kreq_send(&ev);
}

struct kscsi_cmd {
	int host_no;
	struct scsi_cmd scmd;
};

static inline struct kscsi_cmd *KCMD(struct scsi_cmd *cmd)
{
	return container_of(cmd, struct kscsi_cmd, scmd);
}

int kspace_send_cmd_res(uint64_t nid, int result, struct scsi_cmd *cmd)
{
	struct kscsi_cmd *kcmd;
	struct tgt_event ev;

	memset(&ev, 0, sizeof(ev));

	dprintf("%p %u %u %d %p %p %u %" PRIu64 "\n", cmd,
		scsi_get_out_length(cmd), scsi_get_in_length(cmd),
		result,
		scsi_get_out_buffer(cmd), scsi_get_in_buffer(cmd),
		cmd->data_dir, cmd->tag);

	kcmd = KCMD(cmd);

	ev.hdr.type = TGT_UEVENT_CMD_RSP;
	ev.p.cmd_rsp.host_no = kcmd->host_no;
	ev.p.cmd_rsp.itn_id = cmd->cmd_itn_id;
	if (scsi_get_data_dir(cmd) == DATA_WRITE) {
		ev.p.cmd_rsp.uaddr = (unsigned long)scsi_get_out_buffer(cmd);
		ev.p.cmd_rsp.len =
			scsi_get_out_length(cmd) - scsi_get_out_resid(cmd);
	} else {
		ev.p.cmd_rsp.uaddr = (unsigned long)scsi_get_in_buffer(cmd);
		ev.p.cmd_rsp.len =
			scsi_get_in_length(cmd) - scsi_get_in_resid(cmd);
	}
	ev.p.cmd_rsp.sense_len = cmd->sense_len;
	ev.p.cmd_rsp.sense_uaddr = (unsigned long) cmd->sense_buffer;
	ev.p.cmd_rsp.result = result;
	ev.p.cmd_rsp.rw = cmd->data_dir;
	ev.p.cmd_rsp.tag = cmd->tag;

	return kreq_send(&ev);
}

static void kern_queue_cmd(struct tgt_event *ev)
{
	int ret = -ENOMEM, tid, scb_len = 16;
	struct kscsi_cmd *kcmd;
	struct scsi_cmd *cmd;

	tid = tgt_bound_target_lookup(ev->p.cmd_req.host_no);
	if (tid < 0) {
		eprintf("can't find a bound target %d\n",
			ev->p.cmd_req.host_no);
		return;
	}

	/* TODO: define scsi_kcmd and move mmap stuff */
	kcmd = zalloc(sizeof(*kcmd) + scb_len);
	if (!kcmd) {
		eprintf("oom %d\n", ev->p.cmd_req.host_no);
		return;
	}

	kcmd->host_no = ev->p.cmd_req.host_no;
	cmd = &kcmd->scmd;
	cmd->cmd_itn_id = ev->p.cmd_req.itn_id;
	cmd->scb = (unsigned char *)cmd + sizeof(*cmd);
	memcpy(cmd->scb, ev->p.cmd_req.scb, scb_len);
	cmd->scb_len = scb_len;
	memcpy(cmd->lun, ev->p.cmd_req.lun, sizeof(cmd->lun));

	cmd->attribute = ev->p.cmd_req.attribute;
	cmd->tag = ev->p.cmd_req.tag;

	scsi_set_data_dir(cmd, scsi_data_dir_opcode(cmd->scb[0]));

	if (scsi_get_data_dir(cmd) == DATA_WRITE)
		scsi_set_out_length(cmd, ev->p.cmd_req.data_len);
	else
		scsi_set_in_length(cmd, ev->p.cmd_req.data_len);

	if (!scsi_is_io_opcode(cmd->scb[0])) {
		char *buf;
		uint32_t data_len;

		data_len = ev->p.cmd_req.data_len;
		/*
		 * fix spc, sbc, etc. they assume that buffer is long
		 * enough.
		 */
		if (data_len < 4096)
			data_len = 4096;

		buf = valloc(data_len);
		if (!buf)
			goto free_kcmd;

		if (scsi_get_data_dir(cmd) == DATA_WRITE)
			scsi_set_out_buffer(cmd, buf);
		else
			scsi_set_in_buffer(cmd, buf);

		memset(buf, 0, data_len);
	}

	ret = target_cmd_queue(tid, cmd);
	if (ret)
		goto free_kcmd;

	return;
free_kcmd:
	/* TODO: send sense properly */
	eprintf("can't queue this command %d\n", ret);
	free(kcmd);
}

static void kern_cmd_done(struct tgt_event *ev)
{
	int tid;
	/* temp hack */
	struct scsi_cmd *cmd;

	tid = tgt_bound_target_lookup(ev->p.cmd_done.host_no);
	if (tid < 0) {
		eprintf("can't find a bound target %d\n",
			ev->p.cmd_done.host_no);
		return;
	}

	cmd = target_cmd_lookup(tid, ev->p.cmd_done.itn_id, ev->p.cmd_done.tag);
	if (cmd) {
		target_cmd_done(cmd);
		if (!cmd_mmapio(cmd)) {
			if (scsi_get_data_dir(cmd) == DATA_WRITE)
				free(scsi_get_out_buffer(cmd));
			else
				free(scsi_get_in_buffer(cmd));
		}
		free(KCMD(cmd));
	} else
		eprintf("unknow command %d %" PRIu64 " %" PRIu64 "\n",
			tid, ev->p.cmd_done.itn_id, ev->p.cmd_done.tag);
}

static int kspace_send_it_nexus_res(int host_no, uint64_t itn_id,
				    uint32_t function, int result)
{
	struct tgt_event ev;

	memset(&ev, 0, sizeof(ev));

	ev.hdr.type = TGT_UEVENT_IT_NEXUS_RSP;
	ev.p.it_nexus_rsp.host_no = host_no;
	ev.p.it_nexus_rsp.itn_id = itn_id;
	ev.p.it_nexus_rsp.function = function;
	ev.p.it_nexus_rsp.result = result;

	return kreq_send(&ev);
}

static void kern_it_nexus_request(struct tgt_event *ev)
{
	int tid, ret, host_no;
	uint32_t function = ev->p.it_nexus_req.function;
	uint64_t itn_id = ev->p.it_nexus_req.itn_id;

	host_no = ev->p.it_nexus_req.host_no;
	tid = tgt_bound_target_lookup(host_no);
	if (tid < 0) {
		eprintf("can't find a bound target %d\n", host_no);
		return;
	}

	if (function)
		ret = it_nexus_destroy(tid, itn_id);
	else
		ret = it_nexus_create(tid, itn_id, host_no, NULL);

	kspace_send_it_nexus_res(host_no, itn_id, function, ret);
}

static void kern_mgmt_request(struct tgt_event *ev)
{
	int tid;

	tid = tgt_bound_target_lookup(ev->p.tsk_mgmt_req.host_no);
	if (tid < 0) {
		eprintf("can't find a bound target %d\n",
			ev->p.tsk_mgmt_req.host_no);
		return;
	}

	target_mgmt_request(tid, ev->p.tsk_mgmt_req.itn_id,
			    ev->p.tsk_mgmt_req.mid,
			    ev->p.tsk_mgmt_req.function,
			    ev->p.tsk_mgmt_req.lun,
			    ev->p.tsk_mgmt_req.tag,
			    ev->p.cmd_done.host_no);
}

static void kern_event_handler(int fd, int events, void *data)
{
	struct tgt_event *ev;
retry:
	ev = head_ring_hdr(&kuring);
	if (!ev->hdr.status)
		return;

	dprintf("event %u %u\n", kuring.idx, ev->hdr.type);

	switch (ev->hdr.type) {
	case TGT_KEVENT_CMD_REQ:
		kern_queue_cmd(ev);
		break;
	case TGT_KEVENT_CMD_DONE:
		kern_cmd_done(ev);
		break;
	case TGT_KEVENT_IT_NEXUS_REQ:
		kern_it_nexus_request(ev);
		break;
	case TGT_KEVENT_TSK_MGMT_REQ:
		kern_mgmt_request(ev);
		break;
	default:
		eprintf("unknown event %u\n", ev->hdr.type);
	}

	ev->hdr.status = 0;
	ring_index_inc(&kuring);

	goto retry;
}

#define CHRDEV_PATH "/dev/tgt"

static int tgt_miscdev_init(char *path, int *fd)
{
	int major, minor, err;
	FILE *fp;
	char buf[64];

	fp = fopen("/sys/class/misc/tgt/dev", "r");
	if (!fp) {
		eprintf("Cannot open control path to the driver\n");
		return -1;
	}

	if (!fgets(buf, sizeof(buf), fp))
		goto out;

	if (sscanf(buf, "%d:%d", &major, &minor) != 2)
		goto out;

	unlink(path);
	err = mknod(path, (S_IFCHR | 0600), makedev(major, minor));
	if (err)
		goto out;

	*fd = open(path, O_RDWR);
	if (*fd < 0) {
		eprintf("cannot open %s, %m\n", path);
		goto out;
	}

	fclose(fp);

	return 0;
out:
	fclose(fp);
	return -errno;
}

int kreq_init(void)
{
	int err, size = TGT_RING_SIZE;
	char *buf;

	err = tgt_miscdev_init(CHRDEV_PATH, &chrfd);
	if (err)
		return err;

	if (size < pagesize)
		size = pagesize;

	buf = mmap(NULL, size * 2, PROT_READ | PROT_WRITE, MAP_SHARED, chrfd, 0);
	if (buf == MAP_FAILED) {
		eprintf("fail to mmap, %m\n");
		close(chrfd);
		return -EINVAL;
	}

	tgt_ring_pages = size >> pageshift;
	tgt_event_per_page = pagesize / sizeof(struct tgt_event);
	tgt_max_events = tgt_event_per_page * tgt_ring_pages;

	kuring.idx = ukring.idx = 0;
	kuring.buf = buf;
	ukring.buf = buf + size;

	err = tgt_event_add(chrfd, EPOLLIN, kern_event_handler, NULL);
	if (err)
		close(chrfd);
	return err;
}
