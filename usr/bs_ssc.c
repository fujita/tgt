/*
 * SCSI stream command processing backing store
 *
 * Copyright (C) 2008 Mark Harvey markh794@gmail.com
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

#include <linux/fs.h>
#include <sys/epoll.h>

#include "list.h"
#include "util.h"
#include "tgtd.h"
#include "scsi.h"
#include "bs_thread.h"

#include "media.h"
#include "bs_ssc.h"
#include "ssc.h"

static inline uint32_t ssc_get_block_length(struct scsi_lu *lu)
{
	return get_unaligned_be24(lu->mode_block_descriptor + 5);
}

/* I'm sure there is a more efficent method then this */
static int32_t be24_to_2comp(uint8_t *c)
{
	int count;
	count = (c[0] << 16) | (c[1] << 8) | c[2];
	if (c[1] & 0x80)
		count += (0xff << 24);
	return count;
}

static uint32_t be24_to_uint(uint8_t *c)
{
	return (c[0] << 16) | (c[1] << 8) | c[2];
}

static int skip_next_header(struct scsi_lu *lu)
{
	ssize_t rd;
	struct ssc_info *ssc = dtype_priv(lu);
	struct blk_header *h = ssc->c_blk;

	/* FIXME: Need a lock around this read */
	rd = pread(lu->fd, h, sizeof(struct blk_header), h->next);
	if (rd != sizeof(struct blk_header))
		return 1;
	return 0;
}

static int skip_prev_header(struct scsi_lu *lu)
{
	ssize_t rd;
	struct ssc_info *ssc = dtype_priv(lu);
	struct blk_header *h = ssc->c_blk;

	/* FIXME: Need a lock around this read */
	rd = pread(lu->fd, h, sizeof(struct blk_header), h->prev);
	if (rd != sizeof(struct blk_header))
		return 1;
	if (h->blk_type == BLK_BOT)
		return skip_next_header(lu);
	return 0;
}

static int resp_rewind(struct scsi_lu *lu)
{
	int fd;
	ssize_t rd;
	struct ssc_info *ssc = dtype_priv(lu);
	struct blk_header *h;

	h = ssc->c_blk;
	fd = lu->fd;

	eprintf("*** Backing store fd: %s %d %d ***\n", lu->path, lu->fd, fd);

	rd = pread(fd, h, sizeof(struct blk_header), 0);
	if (rd < 0)
		eprintf("Could not read %d bytes:%m\n",
				(int)sizeof(struct blk_header));
	if (rd != sizeof(struct blk_header))
		return 1;

	return skip_next_header(lu);
}

static int append_blk(struct scsi_cmd *cmd, uint8_t *data,
		 int size, int orig_sz, int type)
{
	int fd;
	struct blk_header *curr;
	struct blk_header *eod;
	struct ssc_info *ssc;
	ssize_t ret;

	ssc = dtype_priv(cmd->dev);
	fd = cmd->dev->fd;

	eod = zalloc(sizeof(struct blk_header));
	if (!eod) {
		eprintf("Failed to malloc %" PRId64 " bytes\n",
						(uint64_t)sizeof(eod));
		return -ENOMEM;
	}

	eprintf("B4 update     : prev/curr/next"
		" <%" PRId64 "/%" PRId64 "/%" PRId64 "> type: %d,"
		" num: %" PRIx64 ", ondisk sz: %d, about to write %d\n",
			ssc->c_blk->prev, ssc->c_blk->curr, ssc->c_blk->next,
			ssc->c_blk->blk_type, ssc->c_blk->blk_num,
			ssc->c_blk->ondisk_sz, size);

	/* FIXME: Need lock protection around this */
	curr = ssc->c_blk;
	curr->next = curr->curr + size + sizeof(struct blk_header);
	curr->blk_type = type;
	curr->ondisk_sz = size;
	curr->blk_sz = orig_sz;
	eod->prev = curr->curr;
	eod->curr = curr->next;
	eod->next = curr->next;
	eod->ondisk_sz = 0;
	eod->blk_sz = 0;
	eod->blk_type = BLK_EOD;
	eod->blk_num = curr->blk_num + 1;
	eod->a = 'A';
	eod->z = 'Z';
	ssc->c_blk = eod;
	/* End of protection */

	eprintf("After update  : prev/curr/next"
		" <%" PRId64 "/%" PRId64 "/%" PRId64 "> type: %d,"
		" num: %" PRIx64 ", ondisk sz: %d\n",
			curr->prev, curr->curr, curr->next,
			curr->blk_type, curr->blk_num,
			curr->ondisk_sz);

	eprintf("EOD blk header: prev/curr/next"
		" <%" PRId64 "/%" PRId64 "/%" PRId64 "> type: %d,"
		" num: %" PRIx64 ", ondisk sz: %d\n",
			eod->prev, eod->curr, eod->next,
			eod->blk_type, eod->blk_num,
			eod->ondisk_sz);

	/* Rewrite previous header with updated positioning info */
	ret = pwrite(fd, curr, sizeof(struct blk_header), (off_t)curr->curr);
	if (ret != sizeof(struct blk_header)) {
		eprintf("Rewrite of blk header failed: %m\n");
		sense_data_build(cmd, MEDIUM_ERROR, ASC_WRITE_ERROR);
		goto failed_write;
	}
	/* Write new EOD blk header */
	ret = pwrite(fd, eod, sizeof(struct blk_header), (off_t)eod->curr);
	if (ret != sizeof(struct blk_header)) {
		eprintf("Write of EOD blk header failed: %m\n");
		sense_data_build(cmd, MEDIUM_ERROR, ASC_WRITE_ERROR);
		goto failed_write;
	}

	/* Write any data */
	if (size) {
		ret = pwrite(fd, data, size,
			(off_t)curr->curr + sizeof(struct blk_header));
		if (ret != size) {
			eprintf("Write of data failed: %m\n");
			sense_data_build(cmd, MEDIUM_ERROR, ASC_WRITE_ERROR);
			goto failed_write;
		}
	}
	/* Write new EOD blk header */

	free(curr);
	return SAM_STAT_GOOD;

failed_write:
	free(curr);
	return SAM_STAT_CHECK_CONDITION;
}

static int prev_filemark(struct scsi_cmd *cmd)
{
	struct ssc_info *ssc = dtype_priv(cmd->dev);

	if (skip_prev_header(cmd->dev)) {
		sense_data_build(cmd, MEDIUM_ERROR, ASC_MEDIUM_FORMAT_CORRUPT);
		return SAM_STAT_CHECK_CONDITION;
	}
	while (ssc->c_blk->blk_type != BLK_FILEMARK)
		if (skip_prev_header(cmd->dev)) {
			sense_data_build(cmd, MEDIUM_ERROR,
						ASC_MEDIUM_FORMAT_CORRUPT);
			return SAM_STAT_CHECK_CONDITION;
		}

		if (ssc->c_blk->blk_type == BLK_BOT) {
			skip_next_header(cmd->dev); /* Can't leave at BOT */
			sense_data_build(cmd, NO_SENSE, ASC_BOM);
			return SAM_STAT_CHECK_CONDITION;
		}

	return SAM_STAT_GOOD;
}

static int next_filemark(struct scsi_cmd *cmd)
{
	struct ssc_info *ssc = dtype_priv(cmd->dev);

	if (skip_next_header(cmd->dev)) {
		sense_data_build(cmd, MEDIUM_ERROR, ASC_MEDIUM_FORMAT_CORRUPT);
		return SAM_STAT_CHECK_CONDITION;
	}

	while (ssc->c_blk->blk_type != BLK_FILEMARK) {
		if (skip_next_header(cmd->dev)) {
			sense_data_build(cmd, MEDIUM_ERROR,
						ASC_MEDIUM_FORMAT_CORRUPT);
			return SAM_STAT_CHECK_CONDITION;
		}

		if (ssc->c_blk->blk_type == BLK_EOD) {
			sense_data_build(cmd, NO_SENSE, ASC_END_OF_DATA);
			return SAM_STAT_CHECK_CONDITION;
		}
	}

	return SAM_STAT_GOOD;
}

static int space_filemark(struct scsi_cmd *cmd, int32_t count)
{
	dprintf("*** space %d filemark%s ***\n", count,
			((count > 1) || (count < 0)) ? "s" : "");
	while (count != 0) {
		if (count > 0) {
			if (next_filemark(cmd)) {
				return SAM_STAT_CHECK_CONDITION;
				break;
			}
			count--;
		} else {
			if (prev_filemark(cmd)) {
				return SAM_STAT_CHECK_CONDITION;
				break;
			}
			count++;
		}
	}
	return SAM_STAT_GOOD;
}

static int space_blocks(struct scsi_cmd *cmd, int32_t count)
{
	struct ssc_info *ssc = dtype_priv(cmd->dev);

	dprintf("*** space %d block%s ***\n", count,
			((count > 1) || (count < 0)) ? "s" : "");
	while (count != 0) {
		if (count > 0) {
			if (skip_next_header(cmd->dev)) {
				sense_data_build(cmd, MEDIUM_ERROR,
						ASC_MEDIUM_FORMAT_CORRUPT);
				return SAM_STAT_CHECK_CONDITION;
			}
			if (ssc->c_blk->blk_type == BLK_EOD) {
				sense_data_build(cmd, NO_SENSE,
						ASC_END_OF_DATA);
				return SAM_STAT_CHECK_CONDITION;
			}
			count--;
		} else {
			if (skip_prev_header(cmd->dev)) {
				sense_data_build(cmd, MEDIUM_ERROR,
						ASC_MEDIUM_FORMAT_CORRUPT);
				return SAM_STAT_CHECK_CONDITION;
			}
			if (ssc->c_blk->blk_type == BLK_BOT) {
				/* Can't leave at BOT */
				skip_next_header(cmd->dev);

				sense_data_build(cmd, NO_SENSE, ASC_BOM);
				return SAM_STAT_CHECK_CONDITION;
			}
			count++;
		}
	}
	return SAM_STAT_GOOD;
}

/* Return error - util written */
static int resp_var_read(struct scsi_cmd *cmd, uint8_t *buf, uint32_t length)
{
	sense_data_build(cmd, ILLEGAL_REQUEST, ASC_INVALID_FIELD_IN_CDB);
	return 0;
}

static int resp_fixed_read(struct scsi_cmd *cmd, uint8_t *buf, uint32_t length)
{
	struct ssc_info *ssc;
	int i, ret;
	int count;
	ssize_t residue;
	int fd;
	uint32_t block_length = ssc_get_block_length(cmd->dev);

	count = be24_to_uint(&cmd->scb[2]);
	ssc = dtype_priv(cmd->dev);
	fd = cmd->dev->fd;
	ret = 0;

	for (i = 0; i < count; i++) {
		if (ssc->c_blk->blk_type == BLK_FILEMARK) {
			eprintf("Oops - found filemark\n");
			sense_data_build(cmd, NO_SENSE, ASC_MARK);
/* FIXME: Need to update sense buffer with remaining byte count. */
			goto rd_err;
		}

		if (block_length != ssc->c_blk->blk_sz) {
			eprintf("block size mismatch %d vs %d\n",
				block_length, ssc->c_blk->blk_sz);
			sense_data_build(cmd, MEDIUM_ERROR,
						ASC_MEDIUM_FORMAT_CORRUPT);
			goto rd_err;
		}

		residue = pread(fd, buf, block_length,
				ssc->c_blk->curr + sizeof(struct blk_header));
		if (block_length != residue) {
			eprintf("Could only read %d bytes, not %d\n",
					(int)residue, block_length);
			sense_data_build(cmd, MEDIUM_ERROR, ASC_READ_ERROR);
			goto rd_err;
		}
		ret += block_length;
		buf += block_length;

		if (skip_next_header(cmd->dev)) {
			eprintf("Could not read next header\n");
			sense_data_build(cmd, MEDIUM_ERROR,
						ASC_MEDIUM_FORMAT_CORRUPT);
			goto rd_err;
		}
	}
	return ret;

rd_err:
	return 0;
}

static void tape_rdwr_request(struct scsi_cmd *cmd)
{
	struct ssc_info *ssc;
	int ret, code;
	uint32_t length, i, transfer_length, residue;
	int result = SAM_STAT_GOOD;
	uint8_t *buf;
	int32_t count;
	int8_t fixed;
	int8_t sti;
	uint32_t block_length = ssc_get_block_length(cmd->dev);

	ret = 0;
	length = 0;
	i = 0;
	transfer_length = 0;
	residue = 0;
	code = 0;
	ssc = dtype_priv(cmd->dev);

	switch (cmd->scb[0]) {
	case REZERO_UNIT:
		eprintf("**** Rewind ****\n");
		if (resp_rewind(cmd->dev)) {
			sense_data_build(cmd,
				MEDIUM_ERROR, ASC_SEQUENTIAL_POSITION_ERR);
			result = SAM_STAT_CHECK_CONDITION;
		}
		break;

	case WRITE_FILEMARKS:
		ret = be24_to_uint(&cmd->scb[2]);
		eprintf("*** Write %d filemark%s ***\n", ret,
			((ret > 1) || (ret < 0)) ? "s" : "");

		for (i = 0; i < ret; i++)
			append_blk(cmd, scsi_get_out_buffer(cmd), 0,
					0, BLK_FILEMARK);

		break;

	case READ_6:
		fixed = cmd->scb[1] & 1;
		sti = cmd->scb[1] & 2;

		if (fixed && sti) {
			sense_data_build(cmd, ILLEGAL_REQUEST,
						ASC_INVALID_FIELD_IN_CDB);
			result = SAM_STAT_CHECK_CONDITION;
			break;
		}

		length = scsi_get_in_length(cmd);
		count = be24_to_uint(&cmd->scb[2]);
		buf = scsi_get_in_buffer(cmd);

		dprintf("*** READ_6: length %d, count %d, fixed block %s\n",
				length, count, (fixed) ? "Yes" : "No");
		if (fixed)
			ret = resp_fixed_read(cmd, buf, length);
		else
			ret = resp_var_read(cmd, buf, length);

		if (!ret)
			result = SAM_STAT_CHECK_CONDITION;

		eprintf("Executed READ_6, Read %d bytes\n", ret);
		break;

	case WRITE_6:
		fixed = cmd->scb[1] & 1;

		buf = scsi_get_out_buffer(cmd);
		count = be24_to_uint(&cmd->scb[2]);
		length = scsi_get_out_length(cmd);

		if (!fixed) { /* Until supported */
			sense_data_build(cmd, ILLEGAL_REQUEST,
						ASC_INVALID_FIELD_IN_CDB);
			result = SAM_STAT_CHECK_CONDITION;
			break;
		}

		for (i = 0, ret = 0; i < count; i++) {
			if (append_blk(cmd, buf, block_length,
					block_length, BLK_UNCOMPRESS_DATA)) {
				sense_data_build(cmd, MEDIUM_ERROR,
						ASC_WRITE_ERROR);
				result = SAM_STAT_CHECK_CONDITION;
				break;
			}
			buf += block_length;
			ret += block_length;
		}

		dprintf("*** WRITE_6 count: %d, length: %d, ret: %d, fixed: %s,"
			" ssc->blk_sz: %d\n",
			count, length, ret, (fixed) ? "Yes" : "No",
			block_length);

		if (ret != length) {
			sense_data_build(cmd, MEDIUM_ERROR, ASC_WRITE_ERROR);
			result = SAM_STAT_CHECK_CONDITION;
		}
		break;

	case SPACE:
		code = cmd->scb[1] & 0xf;
		count = be24_to_2comp(&cmd->scb[2]);

		if (code == 0) {	/* Logical Blocks */
			result = space_blocks(cmd, count);
			break;
		} else if (code == 1) { /* Filemarks */
			result = space_filemark(cmd, count);
			break;
		} else if (code == 3) { /* End of data */
			while (ssc->c_blk->blk_type != BLK_EOD)
				if (skip_next_header(cmd->dev)) {
					sense_data_build(cmd, MEDIUM_ERROR,
						ASC_MEDIUM_FORMAT_CORRUPT);
					result = SAM_STAT_CHECK_CONDITION;
					break;
				}
		} else { /* Unsupported */
			sense_data_build(cmd, ILLEGAL_REQUEST,
						ASC_INVALID_FIELD_IN_CDB);
			result = SAM_STAT_CHECK_CONDITION;
		}
		break;

	case READ_POSITION:
	{
		int service_action = cmd->scb[1] & 0x1f;
		uint8_t *data = scsi_get_in_buffer(cmd);
		int len = scsi_get_in_length(cmd);

		eprintf("Size of in_buffer = %d\n", len);
		eprintf("Sizeof(buf): %d\n", (int)sizeof(buf));
		eprintf("service action: 0x%02x\n", service_action);

		if (service_action == 0) {	/* Short form - block ID */
			memset(data, 0, 20);
			data[0] = 20;
		} else if (service_action == 1) { /* Short form - vendor uniq */
			memset(data, 0, 20);
			data[0] = 20;
		} else if (service_action == 6) { /* Long form */
			memset(data, 0, 32);
			data[0] = 32;
		} else {
			sense_data_build(cmd, ILLEGAL_REQUEST,
						ASC_INVALID_FIELD_IN_CDB);
			result = SAM_STAT_CHECK_CONDITION;
		}
		break;
	}
	default:
		eprintf("Unknown op code - should never see this\n");
		sense_data_build(cmd, ILLEGAL_REQUEST, ASC_INVALID_OP_CODE);
		result = SAM_STAT_CHECK_CONDITION;
		break;
	}

	dprintf("io done %p %x %d %u\n", cmd, cmd->scb[0], ret, length);

	scsi_set_result(cmd, result);

	if (result != SAM_STAT_GOOD)
		eprintf("io error %p %x %d %d %" PRIu64 ", %m\n",
			cmd, cmd->scb[0], ret, length, cmd->offset);
}

static int bs_tape_init(struct scsi_lu *lu)
{
	struct bs_thread_info *info = BS_THREAD_I(lu);
	return bs_thread_open(info, tape_rdwr_request, 1);
}

static int bs_tape_open(struct scsi_lu *lu, char *path, int *fd, uint64_t *size)
{
	struct ssc_info *ssc;
	char *cart = NULL;
	ssize_t rd;

	ssc = dtype_priv(lu);

	eprintf("### Enter ###\n");
	*fd = backed_file_open(path, O_RDWR | O_LARGEFILE, size);
	if (*fd < 0) {
		eprintf("Could not open %s %m\n", path);
		return *fd;
	}
	eprintf("*** Backing store fd: %d ***\n", *fd);

	if (*size < (sizeof(struct blk_header) + sizeof(struct MAM))) {
		eprintf("backing file too small - not correct media format\n");
		return -1;
	}
	if (!ssc->c_blk)
		ssc->c_blk = zalloc(sizeof(struct blk_header));
	if (!ssc->c_blk) {
		eprintf("malloc(%d) failed\n", (int)sizeof(struct blk_header));
		goto read_failed;
	}

	/* Can't call 'resp_rewind() at this point as lu data not
	 * setup */
	rd = pread(*fd, ssc->c_blk, sizeof(struct blk_header), 0);
	if (rd < sizeof(struct blk_header)) {
		eprintf("Failed to read complete blk header: %d %m\n", (int)rd);
		goto read_failed;
	}

	rd = pread(*fd, &ssc->mam, sizeof(struct MAM), rd);
	if (rd < sizeof(struct MAM)) {
		eprintf("Failed to read MAM: %d %m\n", (int)rd);
		goto read_failed;
	}
	rd = pread(*fd, ssc->c_blk, sizeof(struct blk_header),
					ssc->c_blk->next);
	if (rd < sizeof(struct blk_header)) {
		eprintf("Failed to read complete blk header: %d %m\n", (int)rd);
		goto read_failed;
	}

	switch (ssc->mam.medium_type) {
	case CART_CLEAN:
		cart = "Cleaning cartridge";
		break;
	case CART_DATA:
		cart = "data cartridge";
		break;
	case CART_WORM:
		cart = "WORM cartridge";
		break;
	default:
		cart = "Unknown cartridge type";
		break;
	}

	eprintf("Media size: %d, media type: %s\n",
			ssc->c_blk->blk_sz, cart);
	return 0;

read_failed:
	free(ssc->c_blk);
	ssc->c_blk = NULL;
	return -1;
}

static void bs_tape_exit(struct scsi_lu *lu)
{
	struct bs_thread_info *info = BS_THREAD_I(lu);
	bs_thread_close(info);
}

static void bs_tape_close(struct scsi_lu *lu)
{
	struct ssc_info *ssc;
	ssc = dtype_priv(lu);
	free(ssc->c_blk);
	ssc->c_blk = NULL;
	dprintf("##### Close #####\n");
	close(lu->fd);
}

static int bs_tape_cmd_done(struct scsi_cmd *cmd)
{
	return 0;
}

static struct backingstore_template tape_bst = {
	.bs_name		= "ssc",
	.bs_datasize		= sizeof(struct bs_thread_info),
	.bs_init		= bs_tape_init,
	.bs_exit		= bs_tape_exit,
	.bs_open		= bs_tape_open,
	.bs_close		= bs_tape_close,
	.bs_cmd_submit		= bs_thread_cmd_submit,
	.bs_cmd_done		= bs_tape_cmd_done,
};

__attribute__((constructor)) static void bs_tape_constructor(void)
{
	register_backingstore_template(&tape_bst);
}
