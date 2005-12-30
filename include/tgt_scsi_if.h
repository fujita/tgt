/*
 * (C) 2005 FUJITA Tomonori <tomof@acm.org>
 * (C) 2005 Mike Christie <michaelc@cs.wisc.edu>
 * This code is licenced under the GPL.
 */

#ifndef __TGT_SCSI_IF_H
#define __TGT_SCSI_IF_H

#ifndef MAX_COMMAND_SIZE
#define MAX_COMMAND_SIZE	16
#endif

struct tgt_scsi_cmd {
	uint8_t scb[MAX_COMMAND_SIZE];
	uint8_t lun[8];
	int tags;
} __attribute__ ((aligned (sizeof(uint64_t))));

#endif
