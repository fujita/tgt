/*
 * SCSI target helpers
 *
 * (C) 2005 FUJITA Tomonori <tomof@acm.org>
 * (C) 2005 Mike Christie <michaelc@cs.wisc.edu>
 * This code is licenced under the GPL.
 */

#ifndef __TGT_SCSI_H
#define __TGT_SCSI_H

#include <tgt.h>
#include <scsi/scsi_cmnd.h>

struct scsi_tgt_cmd {
	uint8_t scb[MAX_COMMAND_SIZE];
	uint8_t sense_buff[SCSI_SENSE_BUFFERSIZE];
	int sense_len;
};

static inline struct scsi_tgt_cmd *tgt_cmd_to_scsi(struct tgt_cmd *cmd)
{
	return (struct scsi_tgt_cmd *) cmd->proto_priv;
}

extern int scsi_tgt_sense_copy(struct tgt_cmd *cmd);
#endif
