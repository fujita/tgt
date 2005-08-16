/*
 * (C) 2005 FUJITA Tomonori <tomof@acm.org>
 * This code is licenced under the GPL.
 */

#ifndef __SCSI_TARGET_IF_H
#define __SCSI_TARGET_IF_H

enum stgt_event_type {
	STGT_KEVENT_START = 10,
	STGT_UEVENT_SCSI_CMND_REQ,

	STGT_KEVENT_SCSI_CMND_RES,
};

struct stgt_event {
	union {
		struct {
			uint64_t cid;
			uint32_t size;
		} msg_scsi_cmnd;
	} u;
};

#endif
