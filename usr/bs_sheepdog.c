/*
 * Copyright (C) 2010 FUJITA Tomonori <tomof@acm.org>
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
#include "sheepdog.h"

static void set_medium_error(int *result, uint8_t *key, uint16_t *asc)
{
	*result = SAM_STAT_CHECK_CONDITION;
	*key = MEDIUM_ERROR;
	*asc = ASC_READ_ERROR;
}

static void bs_sheepdog_request(struct scsi_cmd *cmd)
{
	int ret;
	uint32_t length;
	int result = SAM_STAT_GOOD;
	uint8_t key;
	uint16_t asc;
	struct bs_thread_info *info = BS_THREAD_I(cmd->dev);
	struct sheepdog_access_info *ai = (struct sheepdog_access_info *)(info + 1);

	ret = length = 0;
	key = asc = 0;

	switch (cmd->scb[0])
	{
	case SYNCHRONIZE_CACHE:
	case SYNCHRONIZE_CACHE_16:
		break;
	case WRITE_6:
	case WRITE_10:
	case WRITE_12:
	case WRITE_16:
		/* eprintf("%s, %s, %s, %x %u %lu\n", cmd->dev->path, ai->s_token, ai->s_url, */
		/* cmd->scb[0], scsi_get_out_length(cmd), cmd->offset); */

		length = scsi_get_out_length(cmd);
		ret = sd_io(ai, 1, scsi_get_out_buffer(cmd), length, cmd->offset);
		if (ret)
			set_medium_error(&result, &key, &asc);
		break;
	case READ_6:
	case READ_10:
	case READ_12:
	case READ_16:
		/* eprintf("%s, %s, %s, %x %u %lu\n", cmd->dev->path, ai->s_token, ai->s_url, */
		/* cmd->scb[0], scsi_get_in_length(cmd), cmd->offset); */

		length = scsi_get_in_length(cmd);
		ret = sd_io(ai, 0, scsi_get_in_buffer(cmd), length, cmd->offset);
		if (ret)
			set_medium_error(&result, &key, &asc);
		break;
	default:
		break;
	}

	dprintf("io done %p %x %d %u\n", cmd, cmd->scb[0], ret, length);

	scsi_set_result(cmd, result);

	if (result != SAM_STAT_GOOD) {
		eprintf("io error %p %x %d %d %" PRIu64 ", %m\n",
			cmd, cmd->scb[0], ret, length, cmd->offset);
		sense_data_build(cmd, key, asc);
	}
}

static int bs_sheepdog_open(struct scsi_lu *lu, char *path,
			    int *fd, uint64_t *size)
{
	struct bs_thread_info *info = BS_THREAD_I(lu);
	struct sheepdog_access_info *ai =
		(struct sheepdog_access_info *)(info + 1);
	int ret;

	ret = sd_open(ai, path, 0);
	if (ret)
		return ret;

	*size = ai->inode.vdi_size;

	return 0;
}

static void bs_sheepdog_close(struct scsi_lu *lu)
{
}

static int bs_sheepdog_init(struct scsi_lu *lu)
{
	struct bs_thread_info *info = BS_THREAD_I(lu);

	return bs_thread_open(info, bs_sheepdog_request, 1);
}

static void bs_sheepdog_exit(struct scsi_lu *lu)
{
	struct bs_thread_info *info = BS_THREAD_I(lu);

	bs_thread_close(info);
}

static int bs_sheepdog_cmd_done(struct scsi_cmd *cmd)
{
	return 0;
}

static struct backingstore_template sheepdog_bst = {
	.bs_name		= "sheepdog",
	.bs_datasize		= sizeof(struct bs_thread_info)	+ sizeof(struct sheepdog_access_info),
	.bs_open		= bs_sheepdog_open,
	.bs_close		= bs_sheepdog_close,
	.bs_init		= bs_sheepdog_init,
	.bs_exit		= bs_sheepdog_exit,
	.bs_cmd_submit		= bs_thread_cmd_submit,
	.bs_cmd_done		= bs_sheepdog_cmd_done,
};

__attribute__((constructor)) static void __constructor(void)
{
	register_backingstore_template(&sheepdog_bst);
}
