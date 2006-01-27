/*
 * SCSI target netlink interface
 *
 * (C) 2005 FUJITA Tomonori <tomof@acm.org>
 * (C) 2005 Mike Christie <michaelc@cs.wisc.edu>
 * This code is licenced under the GPL.
 */

#ifndef SCSI_TARGET_FRAMEWORK_IF_H
#define SCSI_TARGET_FRAMEWORK_IF_H

enum tgt_event_type {
	/* user -> kernel */
	TGT_UEVENT_START,
	TGT_UEVENT_TARGET_SETUP,
	TGT_UEVENT_CMD_RES,
	TGT_UEVENT_TARGET_BIND,

	/* kernel -> user */
	TGT_KEVENT_RESPONSE,
	TGT_KEVENT_CMD_REQ,
	TGT_KEVENT_CMD_DONE,
};

struct tgt_event {
	/* user-> kernel */
	union {
		struct {
			int host_no;
			int pid;
		} target_bind;
		struct {
			int host_no;
			uint32_t cid;
			uint32_t len;
			int result;
			uint64_t uaddr;
			uint64_t offset;
			uint8_t rw;
			uint8_t try_map;
		} cmd_res;
	} u;

	/* kernel -> user */
	union {
		struct {
			int err;
		} event_res;
		struct {
			int host_no;
			uint32_t cid;
			uint32_t data_len;
			uint64_t dev_id;
		} cmd_req;
		struct {
			int host_no;
			uint32_t cid;
			int result;
		} cmd_done;
	} k;

	/*
	 * I think a pointer is a unsigned long but this struct
	 * gets passed around from the kernel to userspace and
	 * back again so to handle some ppc64 setups where userspace is
	 * 32 bits but the kernel is 64 we do this odd thing
	 */
	uint64_t data[0];
} __attribute__ ((aligned (sizeof(uint64_t))));

#endif
