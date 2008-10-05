/*
 * SCSI Generic I/O backing store
 *
 * Copyright (C) 2008 Alexander Nezhinsky <nezhinsky@gmail.com>
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
#include <linux/major.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include <scsi/sg.h>

#include "list.h"
#include "util.h"
#include "tgtd.h"
#include "scsi.h"

#define BS_SG_RESVD_SZ  (512 * 1024)
#define BS_SG_TIMEOUT	2000

static int graceful_read(int fd, void *p_read, int to_read)
{
	int err;

	while (to_read > 0) {
		err = read(fd, p_read, to_read);
		if (err >= 0) {
			to_read -= err;
			p_read += err;
		} else if (errno == EINTR)
			continue;
		else {
			eprintf("sg device %d read failed, errno: %d\n",
				fd, errno);
			return errno;
		}
	}
	return 0;
}

static int graceful_write(int fd, void *p_write, int to_write)
{
	int err;

	while (to_write > 0) {
		err = write(fd, p_write, to_write);
		if (err >= 0) {
			to_write -= err;
			p_write += err;
		} else if (errno == EINTR)
			continue;
		else {
			eprintf("sg device %d write failed, errno: %d\n",
				fd, errno);
			return errno;
		}
	}
	return 0;
}

static void set_cmd_failed(struct scsi_cmd *cmd)
{
	int result = SAM_STAT_CHECK_CONDITION;
	uint16_t asc = ASC_READ_ERROR;
	uint8_t key = MEDIUM_ERROR;

	scsi_set_result(cmd, result);
	sense_data_build(cmd, key, asc);
}

static int bs_sg_cmd_submit(struct scsi_cmd *cmd)
{
	struct scsi_lu *dev = cmd->dev;
	int fd = dev->fd;
	struct sg_io_hdr io_hdr;
	int err = 0;

	memset(&io_hdr, 0, sizeof(io_hdr));
	io_hdr.interface_id = 'S';
	io_hdr.cmd_len = cmd->scb_len;
	io_hdr.cmdp = cmd->scb;

	if (scsi_get_data_dir(cmd) == DATA_WRITE) {
		io_hdr.dxfer_direction = SG_DXFER_TO_DEV;
		io_hdr.dxfer_len = scsi_get_out_length(cmd);
		io_hdr.dxferp = (void *)scsi_get_out_buffer(cmd);
	} else {
		io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
		io_hdr.dxfer_len = scsi_get_in_length(cmd);
		io_hdr.dxferp = (void *)scsi_get_in_buffer(cmd);
	}
	io_hdr.mx_sb_len = sizeof(cmd->sense_buffer);
	io_hdr.sbp = cmd->sense_buffer;
	io_hdr.timeout = BS_SG_TIMEOUT;
	io_hdr.pack_id = -1;
	io_hdr.usr_ptr = cmd;
	io_hdr.flags |= SG_FLAG_DIRECT_IO;

	err = graceful_write(fd, &io_hdr, sizeof(io_hdr));
	if (!err)
		set_cmd_async(cmd);
	else {
		eprintf("failed to start cmd 0x%p\n", cmd);
		set_cmd_failed(cmd);
	}
	return 0;
}

static void bs_sg_cmd_complete(int fd, int events, void *data)
{
	struct sg_io_hdr io_hdr;
	struct scsi_cmd *cmd;
	int err;

	memset(&io_hdr, 0, sizeof(io_hdr));
	io_hdr.interface_id = 'S';
	io_hdr.pack_id = -1;

	err = graceful_read(fd, &io_hdr, sizeof(io_hdr));
	if (err)
		return;

	cmd = (struct scsi_cmd *)io_hdr.usr_ptr;
	if (!io_hdr.status) {
		scsi_set_out_resid(cmd, io_hdr.resid);
		scsi_set_in_resid(cmd, io_hdr.resid);
	} else {
		cmd->sense_len = io_hdr.sb_len_wr;
		scsi_set_out_resid_by_actual(cmd, 0);
		scsi_set_in_resid_by_actual(cmd, 0);
	}

	cmd->scsi_cmd_done(cmd, io_hdr.status);
}

static int chk_sg_device(char *path)
{
	struct stat st;

	if (stat(path, &st) < 0) {
		eprintf("stat() failed errno: %d\n", errno);
		return -1;
	}

	if (S_ISCHR(st.st_mode) && major(st.st_rdev) == SCSI_GENERIC_MAJOR)
		return 0;
	else
		return -1;
}

static int init_sg_device(int fd)
{
	int t, err;

	err = ioctl(fd, SG_GET_VERSION_NUM, &t);
	if ((err < 0) || (t < 30000)) {
		eprintf("sg driver prior to 3.x\n");
		return -1;
	}

	t = BS_SG_RESVD_SZ;
	err = ioctl(fd, SG_SET_RESERVED_SIZE, &t);
	if (err < 0) {
		eprintf("SG_SET_RESERVED_SIZE errno: %d\n", errno);
		return -1;
	}

	return 0;
}

static int bs_sg_open(struct scsi_lu *lu, char *path, int *fd, uint64_t *size)
{
	int sg_fd, err;

	err = chk_sg_device(path);
	if (err) {
		eprintf("Not recognized %s as an SG device\n", path);
		return -EINVAL;
	}

	sg_fd = open(path, O_RDWR);
	if (sg_fd < 0) {
		eprintf("Could not open %s, %m\n", path);
		return sg_fd;
	}

	err = init_sg_device(sg_fd);
	if (err) {
		eprintf("Failed to initialize sg device %s\n", path);
		return err;
	}

	err = tgt_event_add(sg_fd, EPOLLIN, bs_sg_cmd_complete, NULL);
	if (err) {
		eprintf("Failed to add sg device event %s\n", path);
		return err;
	}

	*fd = sg_fd;
	*size = 0;
	return 0;
}

static void bs_sg_close(struct scsi_lu *lu)
{
	close(lu->fd);
}

static int bs_sg_cmd_done(struct scsi_cmd *cmd)
{
	return 0;
}

static struct backingstore_template sg_bst = {
	.bs_name		= "sg",
	.bs_datasize		= 0,
	.bs_open		= bs_sg_open,
	.bs_close		= bs_sg_close,
	.bs_cmd_submit		= bs_sg_cmd_submit,
	.bs_cmd_done		= bs_sg_cmd_done,
};

__attribute__((constructor)) static void bs_sg_constructor(void)
{
	register_backingstore_template(&sg_bst);
}
