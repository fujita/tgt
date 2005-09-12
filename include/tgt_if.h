/*
 * (C) 2005 FUJITA Tomonori <tomof@acm.org>
 * (C) 2005 Mike Christie <michaelc@cs.wisc.edu>
 * This code is licenced under the GPL.
 */

#ifndef TARGET_FRAMEWORK_IF_H
#define TARGET_FRAMEWORK_IF_H

#define TGT_IPC_NAMESPACE "TGT_IPC_ABSTRACT_NAMESPACE"

enum tgt_event_type {
	/* user -> kernel */
	TGT_UEVENT_START,
	TGT_UEVENT_TARGET_CREATE,
	TGT_UEVENT_TARGET_DESTROY,
	TGT_UEVENT_DEVICE_CREATE,
	TGT_UEVENT_DEVICE_DESTROY,
	TGT_UEVENT_CMND_RES,

	/* kernel -> user */
	TGT_KEVENT_RESPONSE,
	TGT_KEVENT_CMND_REQ,
};

struct tgt_event {
	/* user-> kernel */
	union {
		struct {
			char type[32];
			int nr_cmnds;
		} c_target;
		struct {
			int tid;
		} d_target;
		struct {
			int tid;
			uint64_t dev_id;
			uint32_t flags;
			char type[32];
		} c_device;
		struct {
			int tid;
			uint64_t dev_id;
		} d_device;
		struct {
			uint64_t cid;
			uint32_t len;
			int result;
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
			uint64_t dev_id;
		} cmnd_req;
	} k;
};

#endif
