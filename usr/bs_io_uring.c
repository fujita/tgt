/*
 * io_uring backing store
 *
 * Copyright (C) 2024 Jonathan Frederick <doublej472@gmail.com>
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
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/fs.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <liburing.h>
#include <stdlib.h>

#include "list.h"
#include "util.h"
#include "tgtd.h"
#include "target.h"
#include "scsi.h"
#include <linux/time_types.h>

#define IO_URING_MAX_IODEPTH (1024 * 16)

enum unmap_mode {
	UNMAP_MODE_BLKDISCARD,
	UNMAP_MODE_FALLOCATE,
	UNMAP_MODE_NONE,
};

struct bs_io_uring_info {
	struct io_uring ring;
	struct scsi_lu *lu;
	int evt_fd;
	unsigned int npending;
	unsigned int iodepth;
	enum unmap_mode unmap_mode;
};

static inline struct bs_io_uring_info *BS_IO_URING_I(struct scsi_lu *lu)
{
	return (struct bs_io_uring_info *)((char *)lu + sizeof(*lu));
}

static void cmd_error_sense(struct scsi_cmd *cmd, uint8_t key, uint16_t asc)
{
	scsi_set_result(cmd, SAM_STAT_CHECK_CONDITION);
	sense_data_build(cmd, key, asc);
}

static void bs_io_uring_get_completions_helper(struct bs_io_uring_info *info)
{
	struct io_uring_cqe *cqe;
	unsigned head;
	unsigned i = 0;
	/* read from eventfd returns 8-byte int, fails with the error EINVAL
	   if the size of the supplied buffer is less than 8 bytes */
	uint64_t evts_complete;

	while (1) {
		int ret = read(info->evt_fd, &evts_complete, sizeof(evts_complete));
		if (ret < 0) {
			switch (errno) {
			case EINTR:
				continue;
			case EAGAIN:
				// EAGAIN in non-blocking evt_fd means nothing is available
				return;
			default:
				eprintf("failed to read IO_URING completions, %m\n");
				return;
			}
		}
		break;
	}

	io_uring_for_each_cqe(&info->ring, head, cqe)
	{
		struct scsi_cmd *cmd = (struct scsi_cmd *)io_uring_cqe_get_data(cqe);
		if (cmd != NULL) {
			int result = SAM_STAT_GOOD;
			if (unlikely(cqe->res < 0)) {
				eprintf("error in async operation: %s\n", strerror(-cqe->res));
				sense_data_build(cmd, MEDIUM_ERROR, 0);
				result = SAM_STAT_CHECK_CONDITION;
			}

			target_cmd_io_done(cmd, result);
		}

		info->npending--;
		i++;
	}

	io_uring_cq_advance(&info->ring, i);
}

static int queue_read(struct bs_io_uring_info *info, struct scsi_cmd *cmd)
{
	struct io_uring_sqe *sqe;
	sqe = io_uring_get_sqe(&info->ring);
	if (!sqe) {
		return -1;
	}

	io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE);
	io_uring_sqe_set_data(sqe, cmd);
	io_uring_prep_read(sqe, 0, scsi_get_in_buffer(cmd), scsi_get_in_length(cmd), cmd->offset);
	set_cmd_async(cmd);

	info->npending++;
	io_uring_submit(&info->ring);
	return 0;
}

static int queue_write(struct bs_io_uring_info *info, struct scsi_cmd *cmd)
{
	struct io_uring_sqe *sqe;
	sqe = io_uring_get_sqe(&info->ring);
	if (!sqe) {
		return -1;
	}

	io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE);
	io_uring_sqe_set_data(sqe, cmd);
	io_uring_prep_write(sqe, 0, scsi_get_out_buffer(cmd), scsi_get_out_length(cmd), cmd->offset);
	set_cmd_async(cmd);

	info->npending++;
	io_uring_submit(&info->ring);
	return 0;
}

static int queue_sync(struct bs_io_uring_info *info, struct scsi_cmd *cmd)
{
	struct io_uring_sqe *sqe;
	sqe = io_uring_get_sqe(&info->ring);
	if (!sqe) {
		return -1;
	}

	if (cmd->scb[0] == SYNCHRONIZE_CACHE_16) {
		sqe->off = cmd->offset;
		sqe->len = scsi_get_in_length(cmd);
	}

	io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE);
	io_uring_sqe_set_data(sqe, cmd);
	io_uring_prep_fsync(sqe, 0, IORING_FSYNC_DATASYNC);
	set_cmd_async(cmd);

	info->npending++;
	io_uring_submit(&info->ring);
	return 0;
}

static int queue_unmap(struct bs_io_uring_info *info, struct scsi_cmd *cmd)
{
	uint32_t length = scsi_get_out_length(cmd);
	char *tmpbuf = scsi_get_out_buffer(cmd);

	if (length < 8)
		return 0;

	length -= 8;
	tmpbuf += 8;

	int num_discards = length / 16;
	while (num_discards > 0) {
		uint64_t offset = get_unaligned_be64(&tmpbuf[0]);
		offset = offset << cmd->dev->blk_shift;

		uint32_t tl = get_unaligned_be32(&tmpbuf[8]);
		tl = tl << cmd->dev->blk_shift;

		if (offset + tl > cmd->dev->size) {
			eprintf("UNMAP beyond EOF\n");
			cmd_error_sense(cmd, ILLEGAL_REQUEST, ASC_LBA_OUT_OF_RANGE);
			return 0;
		}

		if (tl > 0) {
			dprintf("unmap offset %lu length %u\n", offset, tl);

			switch (info->unmap_mode) {
			case UNMAP_MODE_FALLOCATE:
#ifdef FALLOC_FL_PUNCH_HOLE
				while (info->npending >= info->iodepth) {
					bs_io_uring_get_completions_helper(info);
				}
				struct io_uring_sqe *sqe;
				sqe = io_uring_get_sqe(&info->ring);
				if (!sqe) {
					return -1;
				}
				io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE);
				if (num_discards == 1) {
					io_uring_sqe_set_data(sqe, cmd);
				} else {
					io_uring_sqe_set_data(sqe, NULL);
					sqe->flags |= IOSQE_IO_LINK;
				}
				dprintf("sending fallocate o: %lu l %u\n", offset, tl);
				io_uring_prep_fallocate(sqe, 0, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, offset, tl);
				io_uring_submit(&info->ring);
				info->npending++;
				set_cmd_async(cmd);
#endif
				break;
			case UNMAP_MODE_BLKDISCARD:
#ifdef BLKDISCARD
				// We have to send a sync request here to use ioctl
				uint64_t range[] = { offset, tl };
				dprintf("sending BLKDISCARD o: %lu l: %lu\n", range[0], range[1]);
				int ret = ioctl(cmd->dev->fd, BLKDISCARD, &range);
				if (ret) {
					eprintf("BLKDISCARD got code %d %s\n", ret, strerror(-ret));
					cmd_error_sense(cmd, HARDWARE_ERROR, ASC_INTERNAL_TGT_FAILURE);
					return ret;
				}
#endif
				break;
			default:
				eprintf("Ignoring UNMAP request\n");
				break;
			}
		}

		length -= 16;
		tmpbuf += 16;
		num_discards -= 1;
	}

	return 0;
}

static int bs_io_uring_cmd_submit(struct scsi_cmd *cmd)
{
	struct scsi_lu *lu = cmd->dev;
	struct bs_io_uring_info *info = BS_IO_URING_I(lu);
	unsigned int scsi_op = (unsigned int)cmd->scb[0];
	int ret;

	while (info->npending >= info->iodepth) {
		bs_io_uring_get_completions_helper(info);
	}

	switch (scsi_op) {
	case WRITE_6:
	case WRITE_10:
	case WRITE_12:
	case WRITE_16:
		ret = queue_write(info, cmd);

		// dprintf("write offset: %lx\n", cmd->offset);
		break;

	case READ_6:
	case READ_10:
	case READ_12:
	case READ_16:
		ret = queue_read(info, cmd);

		// dprintf("read offset: %lx\n", cmd->offset);
		break;
	case SYNCHRONIZE_CACHE:
	case SYNCHRONIZE_CACHE_16:
		if (cmd->scb[1] & 0x2) {
			cmd_error_sense(cmd, ILLEGAL_REQUEST, ASC_INVALID_FIELD_IN_CDB);
			ret = -1;
		} else {
			ret = queue_sync(info, cmd);
		}
		break;
	case UNMAP:
		if (!cmd->dev->attrs.thinprovisioning) {
			cmd_error_sense(cmd, ILLEGAL_REQUEST, ASC_INVALID_FIELD_IN_CDB);
			ret = -1;
		} else {
			ret = queue_unmap(info, cmd);
		}
		break;
	case WRITE_SAME:
	case WRITE_SAME_16:
		dprintf("WRITE_SAME not yet supported for IO_URING backend.\n");
		ret = -1;
		break;
	default:
		dprintf("skipped cmd:%p op:%x\n", cmd, scsi_op);
		ret = 0;
	}

	if (scsi_get_result(cmd) != SAM_STAT_GOOD) {
		eprintf("io error %p %x %d, %m\n", cmd, cmd->scb[0], ret);
	}

	return 0;
}

static void bs_io_uring_get_completions(int fd, int events, void *data)
{
	struct bs_io_uring_info *info = data;
	bs_io_uring_get_completions_helper(info);
}

static int bs_io_uring_open(struct scsi_lu *lu, char *path, int *fd, uint64_t *size)
{
	struct bs_io_uring_info *info = BS_IO_URING_I(lu);
	struct io_uring_params params;
	int ret;
	uint32_t blksize = 0;

	memset(&params, 0, sizeof(params));
	params.flags |= IORING_SETUP_SQPOLL;
	params.sq_thread_idle = 1000;

	eprintf("create io_uring context for tgt:%d lun:%" PRId64 ", max iodepth:%d\n", info->lu->tgt->tid,
		info->lu->lun, info->iodepth);

	ret = io_uring_queue_init_params(info->iodepth, &info->ring, &params);
	if (ret) {
		eprintf("failed to init io_uring queue params, %m\n");
		return ret;
	}

	int afd = eventfd(0, O_NONBLOCK);
	if (afd < 0) {
		eprintf("failed to create eventfd for tgt:%d lun:%" PRId64 ", %m\n", info->lu->tgt->tid, info->lu->lun);
		ret = afd;
		goto close_ctx;
	}
	dprintf("eventfd:%d for tgt:%d lun:%" PRId64 "\n", afd, info->lu->tgt->tid, info->lu->lun);

	ret = tgt_event_add(afd, EPOLLIN, bs_io_uring_get_completions, info);
	if (ret)
		goto close_eventfd;
	info->evt_fd = afd;

	eprintf("open %s, RW for tgt:%d lun:%" PRId64 "\n", path, info->lu->tgt->tid, info->lu->lun);
	*fd = backed_file_open(path, O_RDWR, size, &blksize);
	/* If we get access denied, try opening the file in readonly mode */
	if (*fd == -1 && (errno == EACCES || errno == EROFS)) {
		eprintf("open %s, READONLY for tgt:%d lun:%" PRId64 "\n", path, info->lu->tgt->tid, info->lu->lun);
		*fd = backed_file_open(path, O_RDONLY, size, &blksize);
		lu->attrs.readonly = 1;
	}
	if (*fd < 0) {
		eprintf("failed to open %s, for tgt:%d lun:%" PRId64 ", %m\n", path, info->lu->tgt->tid, info->lu->lun);
		ret = *fd;
		goto remove_tgt_evt;
	}

	eprintf("%s opened successfully for tgt:%d lun:%" PRId64 "\n", path, info->lu->tgt->tid, info->lu->lun);

	struct stat st;
	if (fstat(*fd, &st) < 0) {
		printf("fstat fail\n");
		return -1;
	}

	if (S_ISREG(st.st_mode)) {
		info->unmap_mode = UNMAP_MODE_FALLOCATE;
	} else if (S_ISBLK(st.st_mode)) {
		info->unmap_mode = UNMAP_MODE_BLKDISCARD;
	} else {
		info->unmap_mode = UNMAP_MODE_NONE;
	}

	ret = io_uring_register_files(&info->ring, fd, 1);
	if (ret) {
		eprintf("failed to register buffers: %s\n", strerror(-ret));
		goto remove_tgt_evt;
	}
	ret = io_uring_register_eventfd(&info->ring, info->evt_fd);
	if (ret) {
		eprintf("failed to register eventfd: %s\n", strerror(-ret));
		goto remove_tgt_evt;
	}

	if (!lu->attrs.no_auto_lbppbe)
		update_lbppbe(lu, blksize);

	return 0;

remove_tgt_evt:
	tgt_event_del(afd);
close_eventfd:
	close(afd);
close_ctx:
	io_uring_queue_exit(&info->ring);
	return ret;
}

static void bs_io_uring_close(struct scsi_lu *lu)
{
	close(lu->fd);
}

static tgtadm_err bs_io_uring_init(struct scsi_lu *lu, char *bsopts)
{
	struct bs_io_uring_info *info = BS_IO_URING_I(lu);

	memset(info, 0, sizeof(*info));
	info->lu = lu;
	info->iodepth = IO_URING_MAX_IODEPTH;

	return TGTADM_SUCCESS;
}

static void bs_io_uring_exit(struct scsi_lu *lu)
{
	struct bs_io_uring_info *info = BS_IO_URING_I(lu);
	tgt_event_del(info->evt_fd);
	close(info->evt_fd);
	io_uring_queue_exit(&info->ring);
}

static struct backingstore_template io_uring_bst = {
	.bs_name = "io_uring",
	.bs_datasize = sizeof(struct bs_io_uring_info),
	.bs_init = bs_io_uring_init,
	.bs_exit = bs_io_uring_exit,
	.bs_open = bs_io_uring_open,
	.bs_close = bs_io_uring_close,
	.bs_cmd_submit = bs_io_uring_cmd_submit,
};

__attribute__((constructor)) static void register_bs_module(void)
{
	unsigned char opcodes[] = { ALLOW_MEDIUM_REMOVAL,
				    COMPARE_AND_WRITE,
				    FORMAT_UNIT,
				    INQUIRY,
				    MAINT_PROTOCOL_IN,
				    MODE_SELECT,
				    MODE_SELECT_10,
				    MODE_SENSE,
				    MODE_SENSE_10,
				    ORWRITE_16,
				    PERSISTENT_RESERVE_IN,
				    PERSISTENT_RESERVE_OUT,
				    PRE_FETCH_10,
				    PRE_FETCH_16,
				    READ_10,
				    READ_12,
				    READ_16,
				    READ_6,
				    READ_CAPACITY,
				    RELEASE,
				    REPORT_LUNS,
				    REQUEST_SENSE,
				    RESERVE,
				    SEND_DIAGNOSTIC,
				    SERVICE_ACTION_IN,
				    START_STOP,
				    SYNCHRONIZE_CACHE,
				    SYNCHRONIZE_CACHE_16,
				    TEST_UNIT_READY,
				    UNMAP,
				    VERIFY_10,
				    VERIFY_12,
				    VERIFY_16,
				    WRITE_10,
				    WRITE_12,
				    WRITE_16,
				    WRITE_6,
				    WRITE_VERIFY,
				    WRITE_VERIFY_12,
				    WRITE_VERIFY_16 };
	bs_create_opcode_map(&io_uring_bst, opcodes, ARRAY_SIZE(opcodes));
	register_backingstore_template(&io_uring_bst);
}
