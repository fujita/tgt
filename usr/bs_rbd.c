/*
 * Synchronous rbd image backing store routine
 *
 * modified from bs_rdrw.c:
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
#define _XOPEN_SOURCE 600

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <linux/fs.h>
#include <sys/epoll.h>

#include "list.h"
#include "util.h"
#include "tgtd.h"
#include "scsi.h"
#include "spc.h"
#include "bs_thread.h"

#include "rados/librados.h"
#include "rbd/librbd.h"

/* one cluster connection only */
rados_t cluster;

struct active_rbd {
	char *poolname;
	char *imagename;
	char *snapname;
	rados_ioctx_t ioctx;
	rbd_image_t rbd_image;
};

#define MAX_IMAGES	20
struct active_rbd active_rbds[MAX_IMAGES];

#define RBDP(fd)	(&active_rbds[fd])

static void parse_imagepath(char *path, char **pool, char **image, char **snap)
{
	char *origp = strdup(path);
	char *p, *sep;

	p = origp;
	sep = strchr(p, '/');
	if (sep == NULL) {
		*pool = "rbd";
	} else {
		*sep = '\0';
		*pool = strdup(p);
		p = sep + 1;
	}
	/* p points to image[@snap] */
	sep = strchr(p, '@');
	if (sep == NULL) {
		*snap = "";
	} else {
		*snap = strdup(sep + 1);
		*sep = '\0';
	}
	/* p points to image\0 */
	*image = strdup(p);
	free(origp);
}

static void set_medium_error(int *result, uint8_t *key, uint16_t *asc)
{
	*result = SAM_STAT_CHECK_CONDITION;
	*key = MEDIUM_ERROR;
	*asc = ASC_READ_ERROR;
}

static void bs_sync_sync_range(struct scsi_cmd *cmd, uint32_t length,
			       int *result, uint8_t *key, uint16_t *asc)
{
	int ret;

	ret = rbd_flush(RBDP(cmd->dev->fd)->rbd_image);
	if (ret)
		set_medium_error(result, key, asc);
}

static void bs_rbd_request(struct scsi_cmd *cmd)
{
	int ret;
	uint32_t length;
	int result = SAM_STAT_GOOD;
	uint8_t key;
	uint16_t asc;
#if 0
	/*
	 * This should go in the sense data on error for COMPARE_AND_WRITE, but
	 * there doesn't seem to be any attempt to do so...
	 */

	uint32_t info = 0;
#endif
	char *tmpbuf;
	size_t blocksize;
	uint64_t offset = cmd->offset;
	uint32_t tl     = cmd->tl;
	int do_verify = 0;
	int i;
	char *ptr;
	const char *write_buf = NULL;
	ret = length = 0;
	key = asc = 0;
	struct active_rbd *rbd = RBDP(cmd->dev->fd);

	switch (cmd->scb[0]) {
	case ORWRITE_16:
		length = scsi_get_out_length(cmd);

		tmpbuf = malloc(length);
		if (!tmpbuf) {
			result = SAM_STAT_CHECK_CONDITION;
			key = HARDWARE_ERROR;
			asc = ASC_INTERNAL_TGT_FAILURE;
			break;
		}

		ret = rbd_read(rbd->rbd_image, offset, length, tmpbuf);

		if (ret != length) {
			set_medium_error(&result, &key, &asc);
			free(tmpbuf);
			break;
		}

		ptr = scsi_get_out_buffer(cmd);
		for (i = 0; i < length; i++)
			ptr[i] |= tmpbuf[i];

		free(tmpbuf);

		write_buf = scsi_get_out_buffer(cmd);
		goto write;
	case COMPARE_AND_WRITE:
		/* Blocks are transferred twice, first the set that
		 * we compare to the existing data, and second the set
		 * to write if the compare was successful.
		 */
		length = scsi_get_out_length(cmd) / 2;
		if (length != cmd->tl) {
			result = SAM_STAT_CHECK_CONDITION;
			key = ILLEGAL_REQUEST;
			asc = ASC_INVALID_FIELD_IN_CDB;
			break;
		}

		tmpbuf = malloc(length);
		if (!tmpbuf) {
			result = SAM_STAT_CHECK_CONDITION;
			key = HARDWARE_ERROR;
			asc = ASC_INTERNAL_TGT_FAILURE;
			break;
		}

		ret = rbd_read(rbd->rbd_image, offset, length, tmpbuf);

		if (ret != length) {
			set_medium_error(&result, &key, &asc);
			free(tmpbuf);
			break;
		}

		if (memcmp(scsi_get_out_buffer(cmd), tmpbuf, length)) {
			uint32_t pos = 0;
			char *spos = scsi_get_out_buffer(cmd);
			char *dpos = tmpbuf;

			/*
			 * Data differed, this is assumed to be 'rare'
			 * so use a much more expensive byte-by-byte
			 * comparasion to find out at which offset the
			 * data differs.
			 */
			for (pos = 0; pos < length && *spos++ == *dpos++;
			     pos++)
				;
#if 0
			/* See comment above at declaration */
			info = pos;
#endif
			result = SAM_STAT_CHECK_CONDITION;
			key = MISCOMPARE;
			asc = ASC_MISCOMPARE_DURING_VERIFY_OPERATION;
			free(tmpbuf);
			break;
		}

		/* no DPO bit (cache retention advice) support */
		free(tmpbuf);

		write_buf = scsi_get_out_buffer(cmd) + length;
		goto write;
	case SYNCHRONIZE_CACHE:
	case SYNCHRONIZE_CACHE_16:
		/* TODO */
		length = (cmd->scb[0] == SYNCHRONIZE_CACHE) ? 0 : 0;

		if (cmd->scb[1] & 0x2) {
			result = SAM_STAT_CHECK_CONDITION;
			key = ILLEGAL_REQUEST;
			asc = ASC_INVALID_FIELD_IN_CDB;
		} else
			bs_sync_sync_range(cmd, length, &result, &key, &asc);
		break;
	case WRITE_VERIFY:
	case WRITE_VERIFY_12:
	case WRITE_VERIFY_16:
		do_verify = 1;
	case WRITE_6:
	case WRITE_10:
	case WRITE_12:
	case WRITE_16:
		length = scsi_get_out_length(cmd);
		write_buf = scsi_get_out_buffer(cmd);
write:
		ret = rbd_write(rbd->rbd_image, offset, length, write_buf);
		if (ret == length) {
			struct mode_pg *pg;

			/*
			 * it would be better not to access to pg
			 * directy.
			 */
			pg = find_mode_page(cmd->dev, 0x08, 0);
			if (pg == NULL) {
				result = SAM_STAT_CHECK_CONDITION;
				key = ILLEGAL_REQUEST;
				asc = ASC_INVALID_FIELD_IN_CDB;
				break;
			}
			if (((cmd->scb[0] != WRITE_6) && (cmd->scb[1] & 0x8)) ||
			    !(pg->mode_data[0] & 0x04))
				bs_sync_sync_range(cmd, length, &result, &key,
						   &asc);
		} else
			set_medium_error(&result, &key, &asc);

		if (do_verify)
			goto verify;
		break;
	case WRITE_SAME:
	case WRITE_SAME_16:
		/* WRITE_SAME used to punch hole in file */
		if (cmd->scb[1] & 0x08) {
			ret = rbd_discard(rbd->rbd_image, offset, tl);
			if (ret != 0) {
				eprintf("Failed to punch hole for WRITE_SAME"
					" command\n");
				result = SAM_STAT_CHECK_CONDITION;
				key = HARDWARE_ERROR;
				asc = ASC_INTERNAL_TGT_FAILURE;
				break;
			}
			break;
		}
		while (tl > 0) {
			blocksize = 1 << cmd->dev->blk_shift;
			tmpbuf = scsi_get_out_buffer(cmd);

			switch (cmd->scb[1] & 0x06) {
			case 0x02: /* PBDATA==0 LBDATA==1 */
				put_unaligned_be32(offset, tmpbuf);
				break;
			case 0x04: /* PBDATA==1 LBDATA==0 */
				/* physical sector format */
				put_unaligned_be64(offset, tmpbuf);
				break;
			}

			ret = rbd_write(rbd->rbd_image, offset, blocksize,
					tmpbuf);
			if (ret != blocksize)
				set_medium_error(&result, &key, &asc);

			offset += blocksize;
			tl     -= blocksize;
		}
		break;
	case READ_6:
	case READ_10:
	case READ_12:
	case READ_16:
		length = scsi_get_in_length(cmd);
		ret = rbd_read(rbd->rbd_image, offset, length,
			       scsi_get_in_buffer(cmd));

		if (ret != length)
			set_medium_error(&result, &key, &asc);

		break;
	case PRE_FETCH_10:
	case PRE_FETCH_16:
		break;
	case VERIFY_10:
	case VERIFY_12:
	case VERIFY_16:
verify:
		length = scsi_get_out_length(cmd);

		tmpbuf = malloc(length);
		if (!tmpbuf) {
			result = SAM_STAT_CHECK_CONDITION;
			key = HARDWARE_ERROR;
			asc = ASC_INTERNAL_TGT_FAILURE;
			break;
		}

		ret = rbd_read(rbd->rbd_image, offset, length, tmpbuf);

		if (ret != length)
			set_medium_error(&result, &key, &asc);
		else if (memcmp(scsi_get_out_buffer(cmd), tmpbuf, length)) {
			result = SAM_STAT_CHECK_CONDITION;
			key = MISCOMPARE;
			asc = ASC_MISCOMPARE_DURING_VERIFY_OPERATION;
		}

		free(tmpbuf);
		break;
	case UNMAP:
		if (!cmd->dev->attrs.thinprovisioning) {
			result = SAM_STAT_CHECK_CONDITION;
			key = ILLEGAL_REQUEST;
			asc = ASC_INVALID_FIELD_IN_CDB;
			break;
		}

		length = scsi_get_out_length(cmd);
		tmpbuf = scsi_get_out_buffer(cmd);

		if (length < 8)
			break;

		length -= 8;
		tmpbuf += 8;

		while (length >= 16) {
			offset = get_unaligned_be64(&tmpbuf[0]);
			offset = offset << cmd->dev->blk_shift;

			tl = get_unaligned_be32(&tmpbuf[8]);
			tl = tl << cmd->dev->blk_shift;

			if (offset + tl > cmd->dev->size) {
				eprintf("UNMAP beyond EOF\n");
				result = SAM_STAT_CHECK_CONDITION;
				key = ILLEGAL_REQUEST;
				asc = ASC_LBA_OUT_OF_RANGE;
				break;
			}

			if (tl > 0) {
				if (rbd_discard(rbd->rbd_image, offset, tl)
				    != 0) {
					eprintf("Failed to punch hole for"
						" UNMAP at offset:%" PRIu64
						" length:%d\n",
						offset, tl);
					result = SAM_STAT_CHECK_CONDITION;
					key = HARDWARE_ERROR;
					asc = ASC_INTERNAL_TGT_FAILURE;
					break;
				}
			}

			length -= 16;
			tmpbuf += 16;
		}
		break;
	default:
		break;
	}

	dprintf("io done %p %x %d %u\n", cmd, cmd->scb[0], ret, length);

	scsi_set_result(cmd, result);

	if (result != SAM_STAT_GOOD) {
		eprintf("io error %p %x %d %d %" PRIu64 ", %m\n",
			cmd, cmd->scb[0], ret, length, offset);
		sense_data_build(cmd, key, asc);
	}
}


static int bs_rbd_open(struct scsi_lu *lu, char *path, int *fd, uint64_t *size)
{
	uint32_t blksize = 0;
	int ret;
	rbd_image_info_t inf;
	char *poolname;
	char *imagename;
	char *snapname;
	struct active_rbd *rbd = NULL;
	int lfd;

	parse_imagepath(path, &poolname, &imagename, &snapname);
	for (lfd = 0; lfd < MAX_IMAGES; lfd++) {
		if (active_rbds[lfd].rbd_image == NULL) {
			rbd = &active_rbds[lfd];
			*fd = lfd;
			break;
		}
	}
	if (!rbd) {
		*fd = -1;
		return -EMFILE;
	}

	rbd->poolname = poolname;
	rbd->imagename = imagename;
	rbd->snapname = snapname;
	eprintf("bs_rbd_open: pool: %s image: %s snap: %s\n",
		poolname, imagename, snapname);

	if ((ret == rados_ioctx_create(cluster, poolname, &rbd->ioctx)) < 0) {
		eprintf("bs_rbd_open: rados_ioctx_create: %d\n", ret);
		return -EIO;
	}
	/* null snap name */
	ret = rbd_open(rbd->ioctx, imagename, &rbd->rbd_image, snapname);
	if (ret < 0) {
		eprintf("bs_rbd_open: rbd_open: %d\n", ret);
		return ret;
	}
	if (rbd_stat(rbd->rbd_image, &inf, sizeof(inf)) < 0) {
		eprintf("bs_rbd_open: rbd_stat: %d\n", ret);
		return ret;
	}
	*size = inf.size;
	blksize = inf.obj_size;

	if (!lu->attrs.no_auto_lbppbe)
		update_lbppbe(lu, blksize);

	return 0;
}

static void bs_rbd_close(struct scsi_lu *lu)
{
	struct active_rbd *rbd = RBDP(lu->fd);

	if (rbd->rbd_image) {
		rbd_close(rbd->rbd_image);
		rados_ioctx_destroy(rbd->ioctx);
		rbd->rbd_image = rbd->ioctx = NULL;
	}
}

static tgtadm_err bs_rbd_init(struct scsi_lu *lu)
{
	tgtadm_err ret = TGTADM_UNKNOWN_ERR;
	int rados_ret;
	struct bs_thread_info *info = BS_THREAD_I(lu);

	rados_ret = rados_create(&cluster, NULL);
	if (rados_ret < 0) {
		eprintf("bs_rbd_init: rados_create: %d\n", rados_ret);
		return ret;
	}
	/* read config from environment and then default files */
	rados_ret = rados_conf_parse_env(cluster, NULL);
	if (rados_ret < 0) {
		eprintf("bs_rbd_init: rados_conf_parse_env: %d\n", rados_ret);
		goto fail;
	}
	rados_ret = rados_conf_read_file(cluster, NULL);
	if (rados_ret < 0) {
		eprintf("bs_rbd_init: rados_conf_read_file: %d\n", rados_ret);
		goto fail;
	}
	rados_ret = rados_connect(cluster);
	if (rados_ret < 0) {
		eprintf("bs_rbd_init: rados_connect: %d\n", rados_ret);
		goto fail;
	}
	ret = bs_thread_open(info, bs_rbd_request, nr_iothreads);
	if (ret == TGTADM_SUCCESS)
		return ret;
fail:
	rados_shutdown(&cluster);
	return ret;
}

static void bs_rbd_exit(struct scsi_lu *lu)
{
	struct bs_thread_info *info = BS_THREAD_I(lu);

	bs_thread_close(info);
	rados_shutdown(&cluster);
}

static struct backingstore_template rbd_bst = {
	.bs_name		= "rbd",
	.bs_datasize		= sizeof(struct bs_thread_info),
	.bs_open		= bs_rbd_open,
	.bs_close		= bs_rbd_close,
	.bs_init		= bs_rbd_init,
	.bs_exit		= bs_rbd_exit,
	.bs_cmd_submit		= bs_thread_cmd_submit,
	.bs_oflags_supported    = O_SYNC | O_DIRECT,
};

static __attribute__((constructor)) void bs_rbd_constructor(void)
{
	register_backingstore_template(&rbd_bst);
}
