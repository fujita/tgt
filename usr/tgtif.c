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
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <asm/types.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <sys/stat.h>
#include <scsi/scsi_tgt_if.h>

#include "list.h"
#include "util.h"
#include "tgtd.h"

struct uring {
	uint32_t idx;
	uint32_t nr_entry;
	int entry_size;
	char *buf;
	int buf_size;
};

static struct uring kuring, ukring;
static int chrfd;

static inline struct rbuf_hdr *head_ring_hdr(struct uring *r)
{
	uint32_t offset = (r->idx & (r->nr_entry - 1)) * r->entry_size;
	return (struct rbuf_hdr *) (r->buf + offset);
}

static void ring_init(struct uring *r, char *buf, int bsize, int esize)
{
	int i;

	esize += sizeof(struct rbuf_hdr);
	r->idx = 0;
	r->buf = buf;
	r->buf_size = bsize;
	r->entry_size = esize;

	bsize /= esize;
	for (i = 0; (1 << i) < bsize && (1 << (i + 1)) <= bsize; i++)
		;
	r->nr_entry = 1 << i;

	dprintf("%u %u\n", r->entry_size, r->nr_entry);
}

int kreq_send(struct tgt_event *ev)
{
	struct rbuf_hdr *hdr;
	hdr = head_ring_hdr(&ukring);
	if (hdr->status)
		return -ENOMEM;

	memcpy(hdr->data, ev, sizeof(*ev));
	ukring.idx++;
	hdr->status = 1;

	write(chrfd, ev, 1);

	return 0;
}

int kreq_recv(void)
{
	struct rbuf_hdr *hdr;

	dprintf("nl event %u\n", kuring.idx);

retry:
	hdr = head_ring_hdr(&kuring);
	if (!hdr->status)
		return 0;

	kreq_exec((struct tgt_event *) (hdr->data));
	hdr->status = 0;
	kuring.idx++;

	goto retry;
}

#define CHRDEV_PATH "/dev/tgt"

int kreq_init(int *ki_fd)
{
	int err, fd, size = TGT_RINGBUF_SIZE;
	char *buf;

	err = chrdev_open("tgt", CHRDEV_PATH, 0, &fd);
	if (err)
		return err;

	buf = mmap(NULL, size * 2, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (buf == MAP_FAILED) {
		eprintf("fail to mmap %s\n", strerror(errno));
		close(fd);
		return -EINVAL;
	}

	ring_init(&kuring, buf, size, sizeof(struct tgt_event));
	ring_init(&ukring, buf + size, size, sizeof(struct tgt_event));

	*ki_fd = chrfd = fd;

	return 0;
}
