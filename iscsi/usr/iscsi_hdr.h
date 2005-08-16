/*
 * Copyright (C) 2002-2003 Ardis Technolgies <roman@ardistech.com>
 *
 * Released under the terms of the GNU GPL v2.0.
 */

#ifndef ISCSI_HDR_H
#define ISCSI_HDR_H

#define ISCSI_VERSION			0

#define __packed __attribute__ ((packed))

struct iscsi_hdr {
	u8  opcode;			/* 0 */
	u8  flags;
	u8  spec1[2];
	u8  ahslength;			/* 4 */
	u8  datalength[3];
	u16 lun[4];			/* 8 */
	u32 itt;			/* 16 */
	u32 ttt;			/* 20 */
	u32 sn;				/* 24 */
	u32 exp_sn;			/* 28 */
	u32 max_sn;			/* 32 */
	u32 spec3[3];			/* 36 */
} __packed;				/* 48 */

/* Opcode encoding bits */
#define ISCSI_OP_RETRY			0x80
#define ISCSI_OP_IMMEDIATE		0x40
#define ISCSI_OPCODE_MASK		0x3F

/* Client to Server Message Opcode values */
#define ISCSI_OP_NOOP_OUT		0x00
#define ISCSI_OP_SCSI_CMD		0x01
#define ISCSI_OP_SCSI_TASK_MGT_MSG	0x02
#define ISCSI_OP_LOGIN_CMD		0x03
#define ISCSI_OP_TEXT_CMD		0x04
#define ISCSI_OP_SCSI_DATA		0x05
#define ISCSI_OP_LOGOUT_CMD		0x06
#define ISCSI_OP_SNACK_CMD		0x10

/* Server to Client Message Opcode values */
#define ISCSI_OP_NOOP_IN		0x20
#define ISCSI_OP_SCSI_RSP		0x21
#define ISCSI_OP_SCSI_TASK_MGT_RSP	0x22
#define ISCSI_OP_LOGIN_RSP		0x23
#define ISCSI_OP_TEXT_RSP		0x24
#define ISCSI_OP_SCSI_DATA_RSP		0x25
#define ISCSI_OP_LOGOUT_RSP		0x26
#define ISCSI_OP_R2T_RSP		0x31
#define ISCSI_OP_ASYNC_EVENT		0x32
#define ISCSI_OP_REJECT_MSG		0x3f

struct iscsi_ahs_hdr {
	u16 ahslength;
	u8 ahstype;
} __packed;

#define ISCSI_AHSTYPE_CDB		1
#define ISCSI_AHSTYPE_RLENGTH		2

union iscsi_sid {
	struct {
		u8 isid[6];		/* Initiator Session ID */
		u16 tsih;		/* Target Session ID */
	} id;
	u64 id64;
} __packed;

struct iscsi_text_req_hdr {
	u8  opcode;
	u8  flags;
	u16 rsvd1;
	u8  ahslength;
	u8  datalength[3];
	u32 rsvd2[2];
	u32 itt;
	u32 ttt;
	u32 cmd_sn;
	u32 exp_stat_sn;
	u32 rsvd3[4];
} __packed;

struct iscsi_text_rsp_hdr {
	u8  opcode;
	u8  flags;
	u16 rsvd1;
	u8  ahslength;
	u8  datalength[3];
	u32 rsvd2[2];
	u32 itt;
	u32 ttt;
	u32 stat_sn;
	u32 exp_cmd_sn;
	u32 max_cmd_sn;
	u32 rsvd3[3];
} __packed;

struct iscsi_login_req_hdr {
	u8  opcode;
	u8  flags;
	u8  max_version;		/* Max. version supported */
	u8  min_version;		/* Min. version supported */
	u8  ahslength;
	u8  datalength[3];
	union iscsi_sid sid;
	u32 itt;			/* Initiator Task Tag */
	u16 cid;			/* Connection ID */
	u16 rsvd1;
	u32 cmd_sn;
	u32 exp_stat_sn;
	u32 rsvd2[4];
} __packed;

struct iscsi_login_rsp_hdr {
	u8  opcode;
	u8  flags;
	u8  max_version;		/* Max. version supported */
	u8  active_version;		/* Active version */
	u8  ahslength;
	u8  datalength[3];
	union iscsi_sid sid;
	u32 itt;			/* Initiator Task Tag */
	u32 rsvd1;
	u32 stat_sn;
	u32 exp_cmd_sn;
	u32 max_cmd_sn;
	u8  status_class;		/* see Login RSP ststus classes below */
	u8  status_detail;		/* see Login RSP Status details below */
	u8  rsvd2[10];
} __packed;

#define ISCSI_FLG_FINAL			0x80
#define ISCSI_FLG_TRANSIT		0x80
#define ISCSI_FLG_CSG_SECURITY		0x00
#define ISCSI_FLG_CSG_LOGIN		0x04
#define ISCSI_FLG_CSG_FULL_FEATURE	0x0c
#define ISCSI_FLG_CSG_MASK		0x0c
#define ISCSI_FLG_NSG_SECURITY		0x00
#define ISCSI_FLG_NSG_LOGIN		0x01
#define ISCSI_FLG_NSG_FULL_FEATURE	0x03
#define ISCSI_FLG_NSG_MASK		0x03

/* Login Status response classes */
#define ISCSI_STATUS_SUCCESS		0x00
#define ISCSI_STATUS_REDIRECT		0x01
#define ISCSI_STATUS_INITIATOR_ERR	0x02
#define ISCSI_STATUS_TARGET_ERR		0x03

/* Login Status response detail codes */
/* Class-0 (Success) */
#define ISCSI_STATUS_ACCEPT		0x00

/* Class-1 (Redirection) */
#define ISCSI_STATUS_TGT_MOVED_TEMP	0x01
#define ISCSI_STATUS_TGT_MOVED_PERM	0x02

/* Class-2 (Initiator Error) */
#define ISCSI_STATUS_INIT_ERR		0x00
#define ISCSI_STATUS_AUTH_FAILED	0x01
#define ISCSI_STATUS_TGT_FORBIDDEN	0x02
#define ISCSI_STATUS_TGT_NOT_FOUND	0x03
#define ISCSI_STATUS_TGT_REMOVED	0x04
#define ISCSI_STATUS_NO_VERSION		0x05
#define ISCSI_STATUS_TOO_MANY_CONN	0x06
#define ISCSI_STATUS_MISSING_FIELDS	0x07
#define ISCSI_STATUS_CONN_ADD_FAILED	0x08
#define ISCSI_STATUS_INV_SESSION_TYPE	0x09
#define ISCSI_STATUS_SESSION_NOT_FOUND	0x0a
#define ISCSI_STATUS_INV_REQ_TYPE	0x0b

/* Class-3 (Target Error) */
#define ISCSI_STATUS_TARGET_ERROR	0x00
#define ISCSI_STATUS_SVC_UNAVAILABLE	0x01
#define ISCSI_STATUS_NO_RESOURCES	0x02

struct iscsi_logout_req_hdr {
	u8  opcode;
	u8  flags;
	u16 rsvd1;
	u8  ahslength;
	u8  datalength[3];
	u32 rsvd2[2];
	u32 itt;
	u16 cid;
	u16 rsvd3;
	u32 cmd_sn;
	u32 exp_stat_sn;
	u32 rsvd4[4];
} __packed;

struct iscsi_logout_rsp_hdr {
	u8  opcode;
	u8  flags;
	u8  response;
	u8  rsvd1;
	u8  ahslength;
	u8  datalength[3];
	u32 rsvd2[2];
	u32 itt;
	u32 rsvd3;
	u32 stat_sn;
	u32 exp_cmd_sn;
	u32 max_cmd_sn;
	u32 rsvd4;
	u16 time2wait;
	u16 time2retain;
	u32 rsvd5;
} __packed;

#endif	/* ISCSI_HDR_H */
