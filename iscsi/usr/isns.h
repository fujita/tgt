/*
 * Defines for iSCSI iSNS support.
 * (C) 2004 Ming Zhang <mingz@ele.uri.edu>
 * This code is licenced under the GPL.
 */

#ifndef __ISNS__
#define __ISNS__

#include "types.h"

/* iSNSP version */
#define ISNSP_VERSION		0x0001

#define ISNS_PORT		3205

/* Entity Protocol */
#define EP_NO_PROTOCOL		1
#define EP_ISCSI		2
#define EP_IFCP			3

/* Node type bit position */
#define NODE_TYPE_CONTROL	29
#define NODE_TYPE_INI		30
#define NODE_TYPE_TARGET	31

/* iSCSI Auth Method */
#define ISCSI_AUTH_KB5		"KB5"
#define ISCSI_AUTH_SPKM1	"SPKM1"
#define ISCSI_AUTH_SPKM2	"SPKM2"
#define ISCSI_AUTH_SRP		"SRP"
#define ISCSI_AUTH_CHAP		"CHAP"

/* DDS Status Enable/Disable */
#define DDS_STATUS_BIT		31

/* DD Feature */
#define DDS_BOOT_BIT		31

/* iSNSP Function ID */
#define FUNC_DevAttrReg		0x0001
#define FUNC_DevAttrQry		0x0002
#define FUNC_DevGetNext		0x0003
#define FUNC_DevDeReg		0x0004
#define FUNC_SCNReg		0x0005
#define FUNC_SCNDeReg		0x0006
#define FUNC_SCNEvent		0x0007
#define FUNC_SCN		0x0008
#define FUNC_DDReg		0x0009
#define FUNC_DDDeReg		0x000A
#define FUNC_DDSReg		0x000B
#define FUNC_DDSDeReg		0x000C
#define FUNC_ESI		0x000D
#define FUNC_Heartbeat		0x000E

#define FUNC_DevAttrRegRsp	0x8001
#define FUNC_DevAttrQryRsp	0x8002
#define FUNC_DevGetNextRsp	0x8003
#define FUNC_DevDeRegRsp	0x8004
#define FUNC_SCNRegRsp		0x8005
#define FUNC_SCNDeRegRsp	0x8006
#define FUNC_SCNEventRsp	0x8007
#define FUNC_SCNRsp		0x8008
#define FUNC_DDRegRsp		0x8009
#define FUNC_DDDeRegRsp		0x800A
#define FUNC_DDSRegRsp		0x800B
#define FUNC_DDSDeRegRsp	0x800C
#define FUNC_ESIRsp		0x800D

/* All iSNSP Flags */
#define LSB				31
#define ISNSP_FLAGS_SENDER_CLIENT	16
#define ISNSP_FLAGS_SENDER_SERVER	17
#define ISNSP_FLAGS_AUTHEN_BLOCK	18
#define ISNSP_FLAGS_REPLACE		19
#define ISNSP_FLAGS_LAST_PDU		20
#define ISNSP_FLAGS_FIRST_PDU		21

#define set_bit_sender_client(x)	(x) |= (1 << (LSB - ISNSP_FLAGS_SENDER_CLIENT))
#define clear_bit_sender_client(x)	(x) &= ~(1 << (LSB - ISNSP_FLAGS_SENDER_CLIENT))
#define set_bit_sender_server(x)	(x) |= (1 << (LSB - ISNSP_FLAGS_SENDER_SERVER))
#define clear_bit_sender_server(x)	(x) &= ~(1 << (LSB - ISNSP_FLAGS_SENDER_SERVER))
#define set_bit_authen_block(x)		(x) |= (1 << (LSB - ISNSP_FLAGS_AUTHEN_BLOCK))
#define clear_bit_authen_block(x)	(x) &= ~(1 << (LSB - ISNSP_FLAGS_AUTHEN_BLOCK))
#define set_bit_replace(x)		(x) |= (1 << (LSB - ISNSP_FLAGS_REPLACE))
#define clear_bit_replace(x)		(x) &= ~(1 << (LSB - ISNSP_FLAGS_REPLACE))
#define set_bit_last_pdu(x)		(x) |= (1 << (LSB - ISNSP_FLAGS_LAST_PDU))
#define clear_bit_last_pdu(x)		(x) &= ~(1 << (LSB - ISNSP_FLAGS_LAST_PDU))
#define set_bit_first_pdu(x)		(x) |= (1 << (LSB - ISNSP_FLAGS_FIRST_PDU))
#define clear_bit_first_pdu(x)		(x) &= ~(1 << (LSB - ISNSP_FLAGS_FIRST_PDU))

/* ALL iSNSP Response Status Code */
#define ISNSP_RSP_SUCC				0
#define ISNSP_RSP_UNKNOWN			1
#define ISNSP_RSP_MSG_FORMAT_ERR 		2
#define ISNSP_RSP_INVAL_REG			3
#define ISNSP_RSP_INVAL_QRY			5
#define ISNSP_RSP_SRC_UNKNOWN			6
#define ISNSP_RSP_SRC_ABSENT			7
#define ISNSP_RSP_SRC_UNAUTH			8
#define ISNSP_RSP_NO_SUCH_ENTRY			9
#define ISNSP_RSP_VERSION_NOT_SUP		10
#define ISNSP_RSP_INTERNAL_ERR			11
#define ISNSP_RSP_BUSY				12
#define ISNSP_RSP_OPT_NOT_UNDERSTOOD		13
#define ISNSP_RSP_INVAL_UPDATE			14
#define ISNSP_RSP_MSG_NOT_SUP			15
#define ISNSP_RSP_SCN_EVENT_REJ			16
#define ISNSP_RSP_SCN_REG_REJ			17
#define ISNSP_RSP_ATTR_UNIMPL			18
#define ISNSP_RSP_FC_DOMAIN_ID_NOT_AVA		19
#define ISNSP_RSP_FC_DOMAIN_ID_NOT_ALL		20
#define ISNSP_RSP_ESI_NOT_AVA			21
#define ISNSP_RSP_INVAL_DEREG			22
#define ISNSP_RSP_REG_FEAT_NOT_SUP		23

/* attribute tag */
#define INVALID_TAG				0xFFFF
#define ATTR_TAG_DELIMITER			0
#define ATTR_TAG_EID				1
#define ATTR_TAG_ENTITY_PROTO			2
#define ATTR_TAG_MANA_IP_ADDR			3
#define ATTR_TAG_TIMESTAMP			4
#define ATTR_TAG_PROTO_VER_RANGE		5
#define ATTR_TAG_REG_PERIOD			6
#define ATTR_TAG_ENTITY_INDEX			7
#define ATTR_TAG_ENTITY_NEXT_INDEX		8
#define ATTR_TAG_ENTITY_ISAKMP_PHASE		11
#define ATTR_TAG_ENTITY_CERT			12
#define ATTR_TAG_PORTAL_IP_ADDR			16
#define ATTR_TAG_PORTAL_PORT			17
#define ATTR_TAG_PORTAL_SYM_NAME		18
#define ATTR_TAG_ESI_INTERVAL			19
#define ATTR_TAG_ESI_PORT			20
#define ATTR_TAG_PORTAL_INDEX			22
#define ATTR_TAG_SCN_PORT			23
#define ATTR_TAG_PORTAL_NEXT_INDEX		24
#define ATTR_TAG_PORTAL_SEC_BITM		27
#define ATTR_TAG_PORTAL_ISAKMP_PHASE1		28
#define ATTR_TAG_PORTAL_ISAKMP_PHASE2		29
#define ATTR_TAG_PORTAL_CERT			31
#define ATTR_TAG_ISCSI_NAME			32
#define ATTR_TAG_NODE_TYPE			33
#define ATTR_TAG_ISCSI_ALIAS			34
#define ATTR_TAG_ISCSI_SCN_BITM			35
#define ATTR_TAG_ISCSI_NODE_INDEX		36
#define ATTR_TAG_WWNN_TOKEN			37
#define ATTR_TAG_ISCSI_NODE_NEXT_INDEX		38
#define ATTR_TAG_ISCSI_AUTH_METHOD		42
#define ATTR_TAG_PG_ISCSI_NAME			48
#define ATTR_TAG_PG_PORTAL_IP_ADDR		49
#define ATTR_TAG_PG_PORTAL_PORT			50
#define ATTR_TAG_PG_TAG				51
#define ATTR_TAG_PG_INDEX			52
#define ATTR_TAG_PG_NEXT_INDEX			53
#define ATTR_TAG_FC_PORT_NAME_WWPN		64
#define ATTR_TAG_PORT_ID			65
#define ATTR_TAG_FC_PORT_TYPE			66
#define ATTR_TAG_SYM_PORT_NAME			67
#define ATTR_TAG_FABRIC_PORT_NAME		68
#define ATTR_TAG_HARD_ADDR			69
#define ATTR_TAG_PORT_IP_ADDR			70
#define ATTR_TAG_CLASS_OF_SERVICE		71
#define ATTR_TAG_FC_4_TYPE			72
#define ATTR_TAG_FC_4_DESC			73
#define ATTR_TAG_FC_4_FEATURE			74
#define ATTR_TAG_IFCP_SCN_BITM			75
#define ATTR_TAG_PORT_ROLE			76
#define ATTR_TAG_PERM_PORT_NAME			77
#define ATTR_TAG_FC_4_TYPE_CODE			95
#define ATTR_TAG_FC_NODE_NAME_WWNN		96
#define ATTR_TAG_SYM_NODE_NAME			97
#define ATTR_TAG_NODE_IP_ADDR			98
#define ATTR_TAG_NODE_IPA			99
#define ATTR_TAG_PROXY_ISCSI_NAME		101
#define ATTR_TAG_SWITCH_NAME			128
#define ATTR_TAG_PREFERRED_ID			129
#define ATTR_TAG_ASSIGNED_ID			130
#define ATTR_TAG_VIRT_FABRIC_ID			132
#define ATTR_TAG_ISNS_SERV_VENDOR_OUI		256
#define ATTR_TAG_DD_SET_ID			2049
#define ATTR_TAG_DD_SET_SYM_NAME		2050
#define ATTR_TAG_DD_SET_STATUS			2051
#define ATTR_TAG_DD_SET_NEXT_ID			2052
#define ATTR_TAG_DD_ID				2065
#define ATTR_TAG_DD_SYM_NAME			2066
#define ATTR_TAG_DD_MEMBER_ISCSI_INDEX		2067
#define ATTR_TAG_DD_MEMBER_ISCSI_NAME		2068
#define ATTR_TAG_DD_MEMBER_FC_PORT_NAME		2069
#define ATTR_TAG_DD_MEMBER_PORTAL_INDEX		2070
#define ATTR_TAG_DD_MEMBER_PORTAL_ADDR		2071
#define ATTR_TAG_DD_MEMBER_PORTAL_TCP		2072
#define ATTR_TAG_DD_FEATURE			2078
#define ATTR_TAG_DD_ID_NEXT_ID			2079

/* attribute maximum possible length */
#define NULL_SIZE				-2
#define VAR_SIZE				-1
#define ATTR_TAG_DELIMITER_SIZE			0
#define ATTR_TAG_EID_SIZE			256
#define ATTR_TAG_ENTITY_PROTO_SIZE		4
#define ATTR_TAG_MANA_IP_ADDR_SIZE		16
#define ATTR_TAG_TIMESTAMP_SIZE			8
#define ATTR_TAG_PROTO_VER_RANGE_SIZE		4
#define ATTR_TAG_REG_PERIOD_SIZE		4
#define ATTR_TAG_ENTITY_INDEX_SIZE		4
#define ATTR_TAG_ENTITY_NEXT_INDEX_SIZE		4
#define ATTR_TAG_ENTITY_ISAKMP_PHASE_SIZE	VAR_SIZE
#define ATTR_TAG_ENTITY_CERT_SIZE		VAR_SIZE
#define ATTR_TAG_PORTAL_IP_ADDR_SIZE		16
#define ATTR_TAG_PORTAL_PORT_SIZE		4
#define ATTR_TAG_PORTAL_SYM_NAME_SIZE		256
#define ATTR_TAG_ESI_INTERVAL_SZIE		4
#define ATTR_TAG_ESI_PORT_SIZE			4
#define ATTR_TAG_PORTAL_INDEX_SIZE		4
#define ATTR_TAG_SCN_PORT_SIZE			4
#define ATTR_TAG_PORTAL_NEXT_INDEX_SIZE		4
#define ATTR_TAG_PORTAL_SEC_BITM_SIZE		4
#define ATTR_TAG_PORTAL_ISAKMP_PHASE1_SIZE	VAR_SIZE
#define ATTR_TAG_PORTAL_ISAKMP_PHASE2_SIZE	VAR_SIZE
#define ATTR_TAG_PORTAL_CERT_SIZE		VAR_SIZE
#define ATTR_TAG_ISCSI_NAME_SIZE		224
#define ATTR_TAG_NODE_TYPE_SIZE			4
#define ATTR_TAG_ISCSI_ALIAS_SIZE		256
#define ATTR_TAG_ISCSI_SCN_BITM_SIZE		4
#define ATTR_TAG_ISCSI_NODE_INDEX_SIZE		4
#define ATTR_TAG_WWNN_TOKEN_SIZE		8
#define ATTR_TAG_ISCSI_NODE_NEXT_INDEX_SIZE	4
#define ATTR_TAG_ISCSI_AUTH_METHOD_SIZE		VAR_SIZE
#define ATTR_TAG_PG_ISCSI_NAME_SIZE		224
#define ATTR_TAG_PG_PORTAL_IP_ADDR_SIZE		16
#define ATTR_TAG_PG_PORTAL_PORT_SIZE		4
#define ATTR_TAG_PG_TAG_SIZE			4
#define ATTR_TAG_PG_INDEX_SIZE			4
#define ATTR_TAG_PG_NEXT_INDEX_SIZE		4
#define ATTR_TAG_FC_PORT_NAME_WWPN_SIZE		8
#define ATTR_TAG_PORT_ID_SIZE			4
#define ATTR_TAG_FC_PORT_TYPE_SIZE		4
#define ATTR_TAG_SYM_PORT_NAME_SIZE		256
#define ATTR_TAG_FABRIC_PORT_NAME_SIZE		8
#define ATTR_TAG_HARD_ADDR_SIZE			4
#define ATTR_TAG_PORT_IP_ADDR_SIZE		16
#define ATTR_TAG_CLASS_OF_SERVICE_SIZE		4
#define ATTR_TAG_FC_4_TYPE_SIZE			32
#define ATTR_TAG_FC_4_DESC_SIZE			256
#define ATTR_TAG_FC_4_FEATURE_SIZE		128
#define ATTR_TAG_IFCP_SCN_BITM_SIZE		4
#define ATTR_TAG_PORT_ROLE_SIZE			4
#define ATTR_TAG_PERM_PORT_NAME_SIZE		8
#define ATTR_TAG_FC_4_TYPE_CODE_SIZE		4
#define ATTR_TAG_FC_NODE_NAME_WWNN_SIZE		8
#define ATTR_TAG_SYM_NODE_NAME_SIZE		256
#define ATTR_TAG_NODE_IP_ADDR_SIZE		16
#define ATTR_TAG_NODE_IPA_SIZE			8
#define ATTR_TAG_PROXY_ISCSI_NAME_SIZE		256
#define ATTR_TAG_SWITCH_NAME_SIZE		8
#define ATTR_TAG_PREFERRED_ID_SIZE		4
#define ATTR_TAG_ASSIGNED_ID_SIZE		4
#define ATTR_TAG_VIRT_FABRIC_ID_SIZE		256
#define ATTR_TAG_ISNS_SERV_VENDOR_OUI_SIZE	4
#define ATTR_TAG_DD_SET_ID_SIZE			4
#define ATTR_TAG_DD_SET_SYM_NAME_SIZE		256
#define ATTR_TAG_DD_SET_STATUS_SIZE		4
#define ATTR_TAG_DD_SET_NEXT_ID_SIZE		4
#define ATTR_TAG_DD_ID_SIZE			4
#define ATTR_TAG_DD_SYM_NAME_SIZE		256
#define ATTR_TAG_DD_MEMBER_ISCSI_INDEX_SIZE	4
#define ATTR_TAG_DD_MEMBER_ISCSI_NAME_SIZE	224
#define ATTR_TAG_DD_MEMBER_FC_PORT_NAME_SIZE	224
#define ATTR_TAG_DD_MEMBER_PORTAL_INDEX_SIZE	4
#define ATTR_TAG_DD_MEMBER_PORTAL_ADDR_SIZE	16
#define ATTR_TAG_DD_MEMBER_PORTAL_TCP_SIZE	4
#define ATTR_TAG_DD_FEATURE_SIZE		4
#define ATTR_TAG_DD_ID_NEXT_ID_SIZE		4

#define REPLACE		1
#define NO_REPLACE	0

/* Be sure this number is still enough */
#define MAX_ISNS_CMD_SIZE	4096
#define MAX_ISNS_RESP_SIZE	4096

/*
 * maximum tlv value length, for current implementation is enough 
 * if really need a larger size, then reallocate a memory and cast
 * the first 4 bytes of attr_val to point to it.
 */
#define MAX_TLV_VALUE_LEN	256

#define Four_Bytes_Aligned(x)	((((x) + 3) >> 2) << 2)

struct tag_len_val {
	u32 attr_tag;
	long attr_len;
	char attr_val[MAX_TLV_VALUE_LEN];
};

struct network_entity {
	struct tag_len_val eid;
	struct tag_len_val entity_proto;
	struct tag_len_val mana_ip_addr;
	struct tag_len_val timestamp;
	struct tag_len_val proto_ver_range;
	struct tag_len_val reg_period;
	struct tag_len_val entity_index;
	struct tag_len_val entity_isakmp_phase;
	struct tag_len_val entity_cert;
	struct network_entity *next;
};

struct portal {
	struct tag_len_val portal_ip_addr;
	struct tag_len_val portal_port;
	struct tag_len_val portal_sym_name;
	struct tag_len_val esi_interval;
	struct tag_len_val esi_port;
	struct tag_len_val portal_index;
	struct tag_len_val scn_port;
	struct tag_len_val portal_sec_bitm;
	struct tag_len_val portal_isakmp_phase1;
	struct tag_len_val portal_isakmp_phase2;
	struct tag_len_val portal_cert;
	struct portal *next;
};

struct portal_group {
	struct tag_len_val pg_iscsi_name;
	struct tag_len_val pg_ip_addr;
	struct tag_len_val pg_portal_port;
	struct tag_len_val pg_tag;
	struct tag_len_val pg_index;
	struct portal_group *next;
};

struct storage_node {
	struct tag_len_val iscsi_name;
	struct tag_len_val iscsi_node_type;
	struct tag_len_val iscsi_alias;
	struct tag_len_val iscsi_scn_bitm;
	struct tag_len_val iscsi_node_index;
	struct tag_len_val wwnn_token;
	struct tag_len_val iscsi_auth_method;
	struct tag_len_val iscsi_node_cert;
	struct storage_node *next;
};

struct discovery_domain {
	struct tag_len_val dd_id;
	struct tag_len_val dd_sym_name;
	struct tag_len_val dd_member_iscsi_index;
	struct tag_len_val dd_member_iscsi_name;
	struct tag_len_val dd_member_portal_index;
	struct tag_len_val dd_member_portal_ip_addr;
	struct tag_len_val dd_member_portal_port;
	struct tag_len_val dd_feature;
	struct discovery_domain *next;
};

struct discovery_domain_set {
	struct tag_len_val dds_id;
	struct tag_len_val dds_sym_name;
	struct tag_len_val dds_status;
	struct discovery_domain_set *next;
};

#define MAX_TLV_CNT		11

typedef union  {
	struct network_entity ne;
	struct portal p;
	struct portal_group pg;
	struct storage_node node;
	struct discovery_domain dd;
	struct discovery_domain_set dds;
	struct tag_len_val tlv[MAX_TLV_CNT];
} TLVLIST;

struct tag_len_val delimiter = {ATTR_TAG_DELIMITER, ATTR_TAG_DELIMITER_SIZE};

struct isns_hdr {
	u16 isnsp_version;
	u16 function_id;
	u16 pdu_length;
	u16 flags;
	u16 transaction_id;
	u16 sequence_id;
};

#define ISNS_HDR_LEN	sizeof(struct isns_hdr)

struct isns_pdu {
	struct isns_hdr *hdr;
	char *pay_load;
	char *authentication_block;
};

/*
 * currently we only use one pdu for one cmd.
 */
struct isns_cmd {
	struct isns_pdu pdu;
	u32 cmd_size;
};

struct isns_resp {
	struct isns_pdu pdu;
	u32 resp_size;
};

int check_isns_hdr(struct isns_hdr *hdr, int function_id);
int check_isns_resp_status(struct isns_pdu *pdu);

#endif
