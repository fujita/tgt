/*
 * (C) 2005 FUJITA Tomonori <tomof@acm.org>
 * This code is licenced under the GPL.
 */

#ifndef __SCSI_TARGET_IF_H
#define __SCSI_TARGET_IF_H

enum stgt_event_type {
	/* user -> kernel */
	STGT_UEVENT_START,
	STGT_UEVENT_SCSI_CMND_RES,

	/* kernel -> user */
	STGT_KEVENT_SCSI_CMND_REQ,
};

struct stgt_event {
	/* user-> kernel */
	union {
		struct {
			uint64_t cid;
			uint32_t size;
		} cmnd_res;
	} u;

	/* kernel -> user */
	union {
		struct {
			uint64_t cid;
			int32_t tid;
			uint32_t lun;
		} cmnd_req;
	} k;
};

#endif
