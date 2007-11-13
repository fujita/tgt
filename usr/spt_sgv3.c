/*
 * SCSI pass through sg3v functions
 *
 * Copyright (C) 2007 FUJITA Tomonori <tomof@acm.org>
 * Copyright (C) 2007 Mike Christie <michaelc@cs.wisc.edu>
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
#include <sys/epoll.h>
#include <limits.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <linux/types.h>
#include <scsi/sg.h>

#include "list.h"
#include "util.h"
#include "tgtd.h"
#include "target.h"
#include "scsi.h"

/*
 * until sgv4 is merged into mainline, we support sgv3 too.
 */
static void sgv3_handler(int fd, int events, void *data)
{
	int i, err;
	struct sg_io_hdr hdrs[64];
	struct scsi_lu *lu = data;

	err = read(lu->fd, hdrs, sizeof(struct sg_io_hdr));
	if (err <= 0)
		return;

	for (i = 0; i < 1; i++) {
		struct scsi_cmd *cmd = (void *) (unsigned long) hdrs[i].usr_ptr;

		dprintf("%p %u %u %u %u\n", cmd,
			hdrs[i].status, hdrs[i].host_status, hdrs[i].driver_status,
			hdrs[i].resid);

		if (hdrs[i].status) {
			cmd->sense_len = hdrs[i].sb_len_wr;
			scsi_set_out_resid_by_actual(cmd, 0);
			scsi_set_in_resid_by_actual(cmd, 0);
		} else {
			scsi_set_out_resid(cmd, hdrs[i].resid);
			scsi_set_in_resid(cmd, hdrs[i].resid);
		}
		target_cmd_io_done(cmd, hdrs[i].status);
	}
}

int spt_sg_open(struct scsi_lu *lu, char *path, int *fd, uint64_t *size)
{
	int err;
	int nr_queue_cmd;

	*size = 0;
	*fd = open(path, O_RDWR | O_NONBLOCK);
	if (*fd < 0)
		return *fd;

	/* workaround */
	nr_queue_cmd = 128;
	err = ioctl(*fd, SG_SET_COMMAND_Q, &nr_queue_cmd);
	if (err) {
		eprintf("can't set the queue depth %d, %m\n", nr_queue_cmd);
		goto close_fd;
	}

	err = tgt_event_add(*fd, EPOLLIN, sgv3_handler, lu);
	if (err) {
		free(lu);
		goto close_fd;
	}

	return 0;
close_fd:
	close(*fd);
	return err;
}

int spt_sg_perform(struct scsi_cmd *cmd)
{
	int ret;
	struct sg_io_hdr hdr;

	memset(&hdr, 0, sizeof(hdr));
	hdr.interface_id = 'S';
	hdr.cmd_len = 16;
	hdr.cmdp = cmd->scb;
	if (scsi_get_data_dir(cmd) == DATA_WRITE) {
		hdr.dxfer_direction = SG_DXFER_TO_DEV;
		hdr.dxferp = scsi_get_out_buffer(cmd);
		hdr.dxfer_len = scsi_get_out_length(cmd);
	} else {
		hdr.dxfer_direction = SG_DXFER_FROM_DEV;
		hdr.dxferp = scsi_get_in_buffer(cmd);
		hdr.dxfer_len = scsi_get_in_length(cmd);
	}
	hdr.mx_sb_len = sizeof(cmd->sense_buffer);
	hdr.sbp = cmd->sense_buffer;
	hdr.flags = SG_FLAG_DIRECT_IO;

	hdr.usr_ptr = (void *)(unsigned long)cmd;

	ret = write(cmd->dev->fd, &hdr, sizeof(hdr));
	if (ret == sizeof(hdr)) {
		set_cmd_async(cmd);
		return 0;
	} else {
		eprintf("%d %m\n", ret);
		return -1;
	}
}
