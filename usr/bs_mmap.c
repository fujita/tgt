/*
 * mmap file backing store routine
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
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

#include "list.h"
#include "util.h"
#include "tgtd.h"
#include "scsi.h"

static int bs_mmap_open(struct scsi_lu *lu, char *path, int *fd, uint64_t *size)
{
	*fd = backed_file_open(path, O_RDWR| O_LARGEFILE, size);

	return *fd >= 0 ? 0 : *fd;
}

static void bs_mmap_close(struct scsi_lu *lu)
{
	close(lu->fd);
}

#define pgcnt(size, offset)	((((size) + ((offset) & (pagesize - 1))) + (pagesize - 1)) >> pageshift)

static int bs_mmap_cmd_submit(struct scsi_cmd *cmd)
{
	int fd = cmd->dev->fd, ret = 0;
	void *p;
	uint64_t addr;
	uint32_t length;

	if (cmd->scb[0] == SYNCHRONIZE_CACHE ||
	    cmd->scb[0] == SYNCHRONIZE_CACHE_16)
		return fsync(fd);

	length = (scsi_get_data_dir(cmd) == DATA_WRITE) ?
		scsi_get_write_len(cmd) : scsi_get_read_len(cmd);

	p = mmap64(NULL, pgcnt(length, cmd->offset) << pageshift,
		   PROT_READ | PROT_WRITE, MAP_SHARED, fd,
		   cmd->offset & ~((1ULL << pageshift) - 1));
	if (p == MAP_FAILED) {
		ret = -EINVAL;
		eprintf("%u %" PRIu64 "\n", length, cmd->offset);
	}

	addr = (unsigned long)p + (cmd->offset & (pagesize - 1));

	if (scsi_get_data_dir(cmd) == DATA_WRITE)
		scsi_set_write_buffer(cmd, (void *)(unsigned long)addr);
	else if (scsi_get_data_dir(cmd) == DATA_READ)
		scsi_set_read_buffer(cmd, (void *)(unsigned long)addr);

	dprintf("%" PRIx64 " %u %" PRIu64 "\n", addr, length, cmd->offset);

	return ret;
}

static int bs_mmap_cmd_done(struct scsi_cmd *cmd)
{
	int err = 0;
	uint64_t addr;
	uint32_t len;

	if (scsi_get_data_dir(cmd) == DATA_WRITE) {
		addr = (unsigned long)scsi_get_write_buffer(cmd);
		len = scsi_get_write_len(cmd);
	} else if (scsi_get_data_dir(cmd) == DATA_READ) {
		addr = (unsigned long)scsi_get_read_buffer(cmd);
		len = scsi_get_read_len(cmd);
	} else
		return 0;

	dprintf("%d %" PRIx64 " %d\n", cmd->mmapped, addr, len);

	if (cmd->mmapped) {
		len = pgcnt(len, (addr & (pagesize - 1))) << pageshift;
		addr &= ~(pagesize - 1);
		err = munmap((void *) (unsigned long) addr, len);
		if (err)
			eprintf("%" PRIx64 " %d\n", addr, len);
	}

	return err;
}

struct backingstore_template mmap_bst = {
	.bs_open		= bs_mmap_open,
	.bs_close		= bs_mmap_close,
	.bs_cmd_submit		= bs_mmap_cmd_submit,
	.bs_cmd_done		= bs_mmap_cmd_done,
};
