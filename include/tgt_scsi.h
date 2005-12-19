/*
 * (C) 2005 FUJITA Tomonori <tomof@acm.org>
 * (C) 2005 Mike Christie <michaelc@cs.wisc.edu>
 * This code is licenced under the GPL.
 */

#ifndef __TGT_SCSI_H
#define __TGT_SCSI_H

#define TMF_RSP_COMPLETE	0x00
#define TMF_RSP_SUCCEEDED	0x01
#define TMF_RSP_REJECTED	0x02
#define TMF_RSP_INCORRECT_LUN	0x03
#define TMF_RSP_TARGET_FAILURE	0x04

/* for transport specific */
#define TMF_RSP_NO_TASK		0x05

#endif
