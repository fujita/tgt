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

struct scsi_tgt_cmnd {
	uint8_t scb[MAX_COMMAND_SIZE];
	uint8_t sense_buff[SCSI_SENSE_BUFFERSIZE];
	int sense_len;
	int tags;
};

static inline struct scsi_tgt_cmnd *tgt_cmnd_to_scsi(struct tgt_cmnd *cmnd)
{
	return (struct scsi_tgt_cmnd *) cmnd->proto_priv;
}

extern int scsi_tgt_sense_copy(struct tgt_cmnd *cmnd);
extern int scsi_tgt_sense_data_build(struct tgt_cmnd *cmnd, uint8_t key,
				     uint8_t ascode, uint8_t ascodeq);
#endif
