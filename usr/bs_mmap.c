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
#include "bs_thread.h"

static void bs_mmap_request(struct scsi_cmd *cmd)
{
	int ret;
	uint32_t length;
	int result = SAM_STAT_GOOD;
	uint8_t key;
	uint16_t asc;

	ret = length = 0;
	key = asc = 0;

	if (cmd->scb[0] != SYNCHRONIZE_CACHE &&
	    cmd->scb[0] != SYNCHRONIZE_CACHE_16)
		eprintf("bug %x\n", cmd->scb[0]);

	/* TODO */
	length = (cmd->scb[0] == SYNCHRONIZE_CACHE) ? 0 : 0;

	if (cmd->scb[1] & 0x2) {
		result = SAM_STAT_CHECK_CONDITION;
		key = ILLEGAL_REQUEST;
		asc = ASC_INVALID_FIELD_IN_CDB;
	} else {
		unsigned int flags =
			SYNC_FILE_RANGE_WAIT_BEFORE| SYNC_FILE_RANGE_WRITE;

		ret = __sync_file_range(cmd->dev->fd, cmd->offset, length, flags);
		if (ret) {
			result = SAM_STAT_CHECK_CONDITION;
			key = MEDIUM_ERROR;
			asc = ASC_READ_ERROR;
		}
	}

	dprintf("io done %p %x %d %u\n", cmd, cmd->scb[0], ret, length);

	scsi_set_result(cmd, result);

	if (result != SAM_STAT_GOOD) {
		eprintf("io error %p %x %d %d %" PRIu64 ", %m\n",
			cmd, cmd->scb[0], ret, length, cmd->offset);
		sense_data_build(cmd, key, asc);
	}
}

static int bs_mmap_open(struct scsi_lu *lu, char *path, int *fd, uint64_t *size)
{
	int ret;
	struct bs_thread_info *info = BS_THREAD_I(lu);

	*fd = backed_file_open(path, O_RDWR| O_LARGEFILE, size);
	if (*fd < 0)
		return *fd;

	ret = bs_thread_open(info, bs_mmap_request);
	if (ret) {
		close(*fd);
		return -1;
	}

	return 0;
}

static void bs_mmap_close(struct scsi_lu *lu)
{
	struct bs_thread_info *info = BS_THREAD_I(lu);

	bs_thread_close(info);
	close(lu->fd);
}

#define pgcnt(size, offset)	((((size) + ((offset) & (pagesize - 1))) + (pagesize - 1)) >> pageshift)

static int bs_mmap_cmd_submit(struct scsi_cmd *cmd)
{
	struct scsi_lu *lu = cmd->dev;
	int fd = lu->fd, ret = 0;
	void *p;
	uint64_t addr;
	uint32_t length;

	if (cmd->scb[0] == SYNCHRONIZE_CACHE ||
	    cmd->scb[0] == SYNCHRONIZE_CACHE_16)
		return bs_thread_cmd_submit(cmd);

	length = (scsi_get_data_dir(cmd) == DATA_WRITE) ?
		scsi_get_out_length(cmd) : scsi_get_in_length(cmd);

	p = mmap64(NULL, pgcnt(length, cmd->offset) << pageshift,
		   PROT_READ | PROT_WRITE, MAP_SHARED, fd,
		   cmd->offset & ~((1ULL << pageshift) - 1));
	if (p == MAP_FAILED) {
		ret = -EINVAL;
		eprintf("%u %" PRIu64 "\n", length, cmd->offset);
	}

	addr = (unsigned long)p + (cmd->offset & (pagesize - 1));

	if (scsi_get_data_dir(cmd) == DATA_WRITE)
		scsi_set_out_buffer(cmd, (void *)(unsigned long)addr);
	else if (scsi_get_data_dir(cmd) == DATA_READ)
		scsi_set_in_buffer(cmd, (void *)(unsigned long)addr);

	dprintf("%" PRIx64 " %u %" PRIu64 "\n", addr, length, cmd->offset);

	return ret;
}

static int bs_mmap_cmd_done(struct scsi_cmd *cmd)
{
	int err = 0;
	uint64_t addr;
	uint32_t len;

	if (scsi_get_data_dir(cmd) == DATA_WRITE) {
		addr = (unsigned long)scsi_get_out_buffer(cmd);
		len = scsi_get_out_length(cmd);
	} else if (scsi_get_data_dir(cmd) == DATA_READ) {
		addr = (unsigned long)scsi_get_in_buffer(cmd);
		len = scsi_get_in_length(cmd);
	} else
		return 0;

	dprintf("%d %" PRIx64 " %d\n", cmd_mmapio(cmd), addr, len);

	if (cmd_mmapio(cmd)) {
		len = pgcnt(len, (addr & (pagesize - 1))) << pageshift;
		addr &= ~(pagesize - 1);
		err = munmap((void *) (unsigned long) addr, len);
		if (err)
			eprintf("%" PRIx64 " %d\n", addr, len);
	}

	return err;
}

static struct backingstore_template mmap_bst = {
	.bs_name		= "mmap",
	.bs_datasize		= sizeof(struct bs_thread_info),
	.bs_open		= bs_mmap_open,
	.bs_close		= bs_mmap_close,
	.bs_cmd_submit		= bs_mmap_cmd_submit,
	.bs_cmd_done		= bs_mmap_cmd_done,
};

__attribute__((constructor)) static void bs_mmap_constructor(void)
{
	register_backingstore_template(&mmap_bst);
}
