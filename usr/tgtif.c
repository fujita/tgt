/*
 * SCSI kernel and user interface
 *
 * Copyright (C) 2006 FUJITA Tomonori <tomof@acm.org>
 * Copyright (C) 2006 Mike Christie <michaelc@cs.wisc.edu>
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

#define aligned_u64 unsigned long long __attribute__((aligned(8)))
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

static inline void ring_index_inc(struct uring *ring)
{
	ring->idx = (ring->idx == TGT_MAX_EVENTS - 1) ? 0 : ring->idx + 1;
}

static inline struct tgt_event *head_ring_hdr(struct uring *ring)
{
	uint32_t pidx, off, pos;

	pidx = ring->idx / TGT_EVENT_PER_PAGE;
	off = ring->idx % TGT_EVENT_PER_PAGE;
	pos = pidx * PAGE_SIZE + off * sizeof(struct tgt_event);

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

int kspace_send_tsk_mgmt_res(uint64_t nid, uint64_t mid, int result)
{
	struct tgt_event ev;

	memset(&ev, 0, sizeof(ev));

	ev.hdr.type = TGT_UEVENT_TSK_MGMT_RSP;
	ev.p.tsk_mgmt_rsp.host_no = it_nexus_to_host_no(nid);
	ev.p.tsk_mgmt_rsp.mid = mid;
	ev.p.tsk_mgmt_rsp.result = result;

	return kreq_send(&ev);
}

int kspace_send_cmd_res(uint64_t nid, int len, int result,
			int rw, uint64_t addr, uint64_t tag)
{
	struct tgt_event ev;

	memset(&ev, 0, sizeof(ev));

	ev.hdr.type = TGT_UEVENT_CMD_RSP;
	ev.p.cmd_rsp.host_no = it_nexus_to_host_no(nid);
	ev.p.cmd_rsp.len = len;
	ev.p.cmd_rsp.result = result;
	ev.p.cmd_rsp.uaddr = addr;
	ev.p.cmd_rsp.rw = rw;
	ev.p.cmd_rsp.tag = tag;

	return kreq_send(&ev);
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
		target_cmd_queue(host_no_to_it_nexus(ev->p.cmd_req.host_no),
				 ev->p.cmd_req.scb,
				 0, 0,
/* 				 ev->k.cmd_req.uaddr, */
				 ev->p.cmd_req.lun, ev->p.cmd_req.data_len,
				 ev->p.cmd_req.attribute, ev->p.cmd_req.tag);
		break;
	case TGT_KEVENT_CMD_DONE:
		target_cmd_done(host_no_to_it_nexus(ev->p.cmd_done.host_no),
				ev->p.cmd_done.tag);
		break;
	case TGT_KEVENT_TSK_MGMT_REQ:
		target_mgmt_request(host_no_to_it_nexus(ev->p.cmd_req.host_no),
				    ev->p.tsk_mgmt_req.mid,
				    ev->p.tsk_mgmt_req.function,
				    ev->p.tsk_mgmt_req.lun,
				    ev->p.tsk_mgmt_req.tag);
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
	err = mknod(path, (S_IFCHR | 0600), (major << 8) | minor);
	if (err)
		goto out;

	*fd = open(path, O_RDWR);
	if (*fd < 0) {
		eprintf("cannot open %s, %m\n", path);
		goto out;
	}

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

	buf = mmap(NULL, size * 2, PROT_READ | PROT_WRITE, MAP_SHARED, chrfd, 0);
	if (buf == MAP_FAILED) {
		eprintf("fail to mmap, %m\n");
		close(chrfd);
		return -EINVAL;
	}

	kuring.idx = ukring.idx = 0;
	kuring.buf = buf;
	ukring.buf = buf + size;

	err = tgt_event_add(chrfd, EPOLLIN, kern_event_handler, NULL);
	if (err)
		close(chrfd);
	return err;
}
