/*
 * (C) 2005 FUJITA Tomonori <tomof@acm.org>
 * This code is licenced under the GPL.
 */

#ifndef __SCSI_TARGET_IF_H
#define __SCSI_TARGET_IF_H

enum stgt_event_type {
	/* user -> kernel */
	STGT_UEVENT_START,
	STGT_UEVENT_DEVICE_CREATE,
	STGT_UEVENT_DEVICE_DESTROY,
	STGT_UEVENT_SCSI_CMND_RES,

	/* kernel -> user */
	STGT_KEVENT_RESPONSE,
	STGT_KEVENT_SCSI_CMND_REQ,
};

struct stgt_event {
	/* user-> kernel */
	union {
		struct {
			int tid;
			uint32_t lun;
			uint32_t flags;
			char type[32];
		} c_device;
		struct {
			int tid;
			uint32_t lun;
		} d_device;
		struct {
			uint64_t cid;
			uint32_t size;
		} cmnd_res;
	} u;

	/* kernel -> user */
	union {
		struct {
			int err;
		} event_res;
		struct {
			uint64_t cid;
			int tid;
			uint32_t lun;
		} cmnd_req;
	} k;
};

#endif
