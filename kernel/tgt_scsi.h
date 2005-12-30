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

#define	tgt_scsi_sense_length(cmd)	(cmd)->bufflen

#endif
