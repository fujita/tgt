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

#define TCLP_BIT            4
#define LONG_BIT            2
#define BT_BIT              1

static void set_medium_error(int *result, uint8_t *key, uint16_t *asc)
{
	*result = SAM_STAT_CHECK_CONDITION;
	*key = MEDIUM_ERROR;
	*asc = ASC_READ_ERROR;
}

static void ssc_sense_data_build(struct scsi_cmd *cmd, uint8_t key,
				 uint16_t asc)
{
	int len = 0xa;
	cmd->sense_buffer[0] = 0x70;
	cmd->sense_buffer[2] = NO_SENSE;
	cmd->sense_buffer[7] = len;
	cmd->sense_buffer[12] = (asc >> 8) & 0xff;
	cmd->sense_buffer[13] = asc & 0xff;
	cmd->sense_len = len + 8;
}

static void rdwr_request(struct scsi_cmd *cmd)
{
	int ret, fd = cmd->dev->fd, code;
	uint32_t length, i, transfer_length, residue;
	int result = SAM_STAT_GOOD;
	uint8_t key;
	uint16_t asc;
	uint8_t buff[512];
	char *buf;
	off_t rew;
	uint64_t curr_pos;
	uint32_t count;

	ret = 0;
	length = 0;
	i = 0;
	key = 0;
	asc = 0;
	transfer_length = 0;
	residue = 0;
	count = 0;
	code = 0;

	switch (cmd->scb[0]) {
	case REZERO_UNIT:
		rew = lseek(fd, 0, SEEK_SET);
		curr_pos = lseek(fd, 0, SEEK_CUR);
		if (ret)
			set_medium_error(&result, &key, &asc);
		eprintf("Rewind Successful, File Pointer at %" PRIu64",%m\n",
			curr_pos);
		break;
	case WRITE_FILEMARKS:
		length = sizeof(buff);
		memset(buff, 28, sizeof(buff));
		ret = write(fd, buff, length);

		if (ret != length)
			set_medium_error(&result, &key, &asc);
		eprintf("Write Filemark Successfull %d\n", ret);
		curr_pos = lseek(fd, 0, SEEK_CUR);
		eprintf("File Pointer at %" PRIu64",%m\n", curr_pos);
		break;
	case READ_6:
		length = scsi_get_in_length(cmd);
		ret = read(fd, scsi_get_in_buffer(cmd), length);
		buf = (char *)(unsigned long)scsi_get_in_buffer(cmd);
		/* buf = (char *)buf; */
		if (ret != length)
			set_medium_error(&result, &key, &asc);
		else {
			for (i = 0; i < ret; i += 512) {
				eprintf("buf[%d]=%d", i, buf[i]);
				if (buf[i] == 28) {
					result = SAM_STAT_CHECK_CONDITION;
					key = NO_SENSE;
					asc = ASC_MARK;
					transfer_length = ((cmd->scb[2] << 16) |
							   (cmd->scb[3] << 8) |
							   (cmd->scb[4]));
/* 					residue = */
/* 						transfer_length - i << 9; */
					residue = (length - i) << 9;
					cmd->sense_buffer[3] = residue >> 24;
					cmd->sense_buffer[3] = residue >> 16;
					cmd->sense_buffer[3] = residue >> 8;
					cmd->sense_buffer[3] = residue;

					eprintf("File Mark Detected at %d,"
						" Residue = %d %m\n",
						i, residue);
				}
			}
		}
		eprintf("Executed READ_6, Read %d bytes\n", ret);
		curr_pos = lseek(fd, 0, SEEK_CUR);
		eprintf("File Pointer at %" PRIu64",%m\n", curr_pos);
		break;
	case WRITE_6:
		length = scsi_get_out_length(cmd);
		ret = write(fd, scsi_get_out_buffer(cmd), length);
		if (ret != length)
			set_medium_error(&result, &key, &asc);
		eprintf("Executed WRITE_6, writen %d bytes\n", ret);
		curr_pos = lseek(fd, 0, SEEK_CUR);
		eprintf("File Pointer at %" PRIu64",%m\n", curr_pos);
		break;
	case SPACE:
		code = cmd->scb[1];
		count = (cmd->scb[2] << 16) | (cmd->scb[3] << 8) |
			(cmd->scb[4]);

		if (code == 0) {
			for (i = 0; i < count; i++) {
				ret = read(fd, buff, sizeof(buff));
				if (ret != sizeof(buff))
					set_medium_error(&result, &key, &asc);

				curr_pos = lseek(fd, 0, SEEK_CUR);
				eprintf("File Pointer at %" PRIu64",%m\n",
					curr_pos);

				if (buff[i*512] == 28) {
					result = SAM_STAT_CHECK_CONDITION;
					key = NO_SENSE;
					asc = ASC_MARK;
				}
			}
		} else if (code == 1) {
			i = 0;
			while (i < count) {
				ret = read(fd, buff, sizeof(buff));
				curr_pos = lseek(fd, 0, SEEK_CUR);
				eprintf("File Pointer at %" PRIu64",%m\n",
					curr_pos);
				if (buff[i*512] == 28)
					i++;
			}
		}
		break;
	case READ_POSITION:
	{
		int tclp = cmd->scb[1] & TCLP_BIT;
		int long_bit = cmd->scb[1] & LONG_BIT;
		int bt = cmd->scb[1] & BT_BIT;
		uint8_t *data;

		eprintf("Size of in_buffer = %d ", scsi_get_in_length(cmd));
		if (tclp == 1 || tclp != long_bit || (bt == 1 && long_bit == 1))
			result = SAM_STAT_CHECK_CONDITION;
		else {
			memset(buff, 0, sizeof(buff));
			data = buff;
			curr_pos = lseek(fd, 0, SEEK_CUR);
			if (curr_pos == 0)
				data[0] = 0xb4;
			else
				data[0] = 0x34;
			memcpy(scsi_get_in_buffer(cmd), data, 20);
		}

		break;
	}
	default:
		break;
	}

	dprintf("io done %p %x %d %u\n", cmd, cmd->scb[0], ret, length);

	scsi_set_result(cmd, result);

	if (result != SAM_STAT_GOOD) {
		eprintf("io error %p %x %d %d %" PRIu64 ", %m\n",
			cmd, cmd->scb[0], ret, length, cmd->offset);
		ssc_sense_data_build(cmd, key, asc);
	}
}


static int bs_ssc_open(struct scsi_lu *lu, char *path, int *fd, uint64_t *size)
{
	int ret;
	struct bs_thread_info *info = BS_THREAD_I(lu);
	uint64_t curr_pos;

	eprintf("In bs_ssc_open\n");
	*fd = backed_file_open(path, O_RDWR | O_LARGEFILE, size);
	if (*fd < 0) {
		eprintf("Error in bs_ssc_open\n");
		return *fd;
	}
	curr_pos = lseek(*fd, 0, SEEK_CUR);
	eprintf("File %s File Pointer at %" PRIu64",%m\n", path, curr_pos);

	ret = bs_thread_open(info, rdwr_request);
	if (ret) {
		close(*fd);
		return -1;
	}

	return 0;
}

static void bs_ssc_close(struct scsi_lu *lu)
{
	struct bs_thread_info *info = BS_THREAD_I(lu);

	bs_thread_close(info);

	close(lu->fd);
}

static int bs_ssc_cmd_done(struct scsi_cmd *cmd)
{
	return 0;
}

static struct backingstore_template ssc_bst = {
	.bs_name		= "ssc",
	.bs_datasize		= sizeof(struct bs_thread_info),
	.bs_open		= bs_ssc_open,
	.bs_close		= bs_ssc_close,
	.bs_cmd_submit		= bs_thread_cmd_submit,
	.bs_cmd_done		= bs_ssc_cmd_done,
};

__attribute__((constructor)) static void bs_ssc_constructor(void)
{
	register_backingstore_template(&ssc_bst);
}
