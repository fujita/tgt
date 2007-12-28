/*
 * Copyright(c) 2007 Intel Corporation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef _FC_ILS_H_
#define	_FC_ILS_H_

/*
 * Fibre Channel Switch - Internal Link Services definitions.
 * From T11 FC-SW-4 Rev 7.5 June 9,2005.
 */
#define	FC_WWN_LEN 8		/* length of world-wide name in bytes */

/*
 * Default time out values (in milliseconds).
 */
#define	FC_DEF_F_S_TOV	    (5 * 1000)	/* fabric stability timeout */
#define	FC_DEF_E_D_TOV	    (2 * 1000)	/* error detection timeout */
#define	FC_DEF_R_A_TOV	    (10 * 1000)	/* resource allocation timeout */
#define	FC_DEF_E_D_PAD	    (4 * 1000)	/* pad for state P5_ELP */
#define	FC_DEF_HELLO_IVL    (20 * 1000)	/* hello interval */
#define	FC_DEF_DEAD_IVL     (80 * 1000)	/* dead interval */

/*
 * ILS Command codes - byte 0 of the frame payload
 */
enum fc_ils_cmd {
	ILS_SW_RJT =	0x01,	/* ILS reject */
	ILS_SW_ACC =	0x02,	/* ILS accept */
	ILS_ELP =	0x10,	/* exchange link parameters */
	ILS_EFP =	0x11,	/* exchange fabric parameters (if subcode 10) */
	ILS_DIA =	0x12,	/* domain ID assigned */
	ILS_RDI =	0x13,	/* request domain ID */
	ILS_HLO =	0x14,	/* hello */
	ILS_LSU =	0x15,	/* link state update */
	ILS_LSA =	0x16,	/* link state acknowledgement */
	ILS_BF =	0x17,	/* build fabric */
	ILS_RCF =	0x18,	/* reconfigure fabric */
	ILS_SW_RSCN =	0x1b,	/* reg. state change notify */
	ILS_DRLIR =	0x1e,	/* dist. registered link incident records */
	ILS_DSCN =	0x20,	/* disconnect class 1 */
	ILS_LOOPD =	0x21,	/* reserved (obsoleted in FC-SW-3) */
	ILS_MR =	0x22,	/* merge request */
	ILS_ACA =	0x23,	/* acquire change auth. */
	ILS_RCA =	0x24,	/* release change auth. */
	ILS_SFC =	0x25,	/* stage fabric config */
	ILS_UFC =	0x26,	/* update fabric config */
	ILS_CEC =	0x29,	/* check E_port connectivity */
	ILS_2A =	0x2a,	/* enhanced subcommands (see below) */
	ILS_ESC =	0x30,	/* exchange switch capabilities */
	ILS_ESS =	0x31,	/* exchange switch support */
	ILS_MRRA =	0x34,	/* merge request res alloc */
	ILS_STR =	0x35,	/* switch trace route */
	ILS_EVFP =	0x36,	/* exch. virt. fab param */
	ILS_FFI =	0x50,	/* fast fabric init for AE */
};

/*
 * Initializer useful for decoding table.
 * Please keep this in sync with the above definitions.
 */
#define	FC_ILS_CMDS_INIT {						\
	[ILS_SW_RJT] =	"ILS reject",					\
	[ILS_SW_ACC] =	"ILS Accept",					\
	[ILS_ELP] =	"exchange link parameters",			\
	[ILS_EFP] =	"exchange fabric parameters",			\
	[ILS_DIA] =	"domain ID assigned",				\
	[ILS_RDI] =	"request domain ID",				\
	[ILS_HLO] =	"hello",					\
	[ILS_LSU] =	"link state update",				\
	[ILS_LSA] =	"link state ack",				\
	[ILS_BF] =	"build fabric",					\
	[ILS_RCF] =	"reconfigure fabric",				\
	[ILS_SW_RSCN] =	"reg. state change notify",			\
	[ILS_DRLIR] =	"dist. registered link incident records",	\
	[ILS_DSCN] =	"disconnect class 1",				\
	[ILS_LOOPD] =	"reserved (obsoleted in FC-SW-3)",		\
	[ILS_MR] =	"merge request",				\
	[ILS_ACA] =	"acquire change auth.",				\
	[ILS_RCA] =	"release change auth.",				\
	[ILS_SFC] =	"stage fabric config",				\
	[ILS_UFC] =	"update fabric config",				\
	[ILS_CEC] =	"check E_port connectivity",			\
	[ILS_2A] =	"enhanced subcommands (see below)",		\
	[ILS_ESC] =	"exchange switch capabilities",			\
	[ILS_ESS] =	"exchange switch support",			\
	[ILS_MRRA] =	"merge request res alloc",			\
	[ILS_STR] =	"switch trace route",				\
	[ILS_EVFP] =	"exch. virt. fab param",			\
	[ILS_FFI] =	"fast fabric init for AE",			\
}

/*
 * Subcommands (byte 1) for FC_ILS_2A
 */
enum fc_ils_2Asub_cmd {
	ILS_EACA =	0x01,	/* Enhanced Acquire Change Authorization */
	ILS_ESFC =	0x02,	/* Enhanced Stage Fabric Configuration */
	ILS_EUFC =	0x03,	/* Enhanced Update Fabric Configuration */
	ILS_ERCA =	0x04,	/* Enhanced Release Change Authorization */
	ILS_TCO =	0x05,	/* Transfer Commit Ownership */
};

/*
 * Reject (FC_ILS_SW_RJT) payload.
 */
struct fc_ils_sw_rjt {
	net8_t		rjt_cmd;	/* command code (0x01) */
	net8_t		_rjt_resvd[4];	/* reserved */
	net8_t		rjt_reason;	/* reason code */
	net8_t		rjt_explan;	/* reason explanation */
	net8_t		rjt_vendor;	/* vendor specific */
};

#define	FC_ILS_SW_RJT_LEN   8	/* expected length of struct */

/*
 * reject reason codes (rjt_reason).
 */
enum fc_ils_rjt_reason {
	ILS_RJT_INVAL =		0x01,	/* invalid SW_ILS command code */
	ILS_RJT_REV =		0x02,	/* invalid revision level */
	ILS_RJT_LOGIC =		0x03,	/* logical error */
	ILS_RJT_SIZE =		0x04,	/* invalid payload size */
	ILS_RJT_BUSY =		0x05,	/* logical busy */
	ILS_RJT_PROT =		0x07,	/* protocol error */
	ILS_RJT_UNAB =		0x09,	/* unable to perform command request */
	ILS_RJT_UNSUP =		0x0b,	/* command not supported */
	ILS_RJT_ATT =		0x0c,	/* invalid attachment */
	ILS_RJT_VENDOR =	0xff,	/* vendor specific error */
};

/*
 * reason code explanation (rjt_explan).
 */
enum fc_ils_rjt_explan {
	ILS_EXPL_NONE =		0x00,	/* No additional explanation */
	ILS_EXPL_UNSUPR =	0x2c,	/* Request not supported */
	ILS_EXPL_UNSUPC =	0x42,	/* Unsupported command */
	ILS_EXPL_INVALR =	0x45,	/* Invalid request */
	/* TBD - above definitions incomplete */
};

/*
 * General name format - used for zoning.
 * See FC-GS-5 Rev 8.2 Section 6.4.8.1.
 * Max name length is 64 characters, plus fill to a multiple of 4 bytes.
 * Valid characters: A-Za-z0-9$-^_ (no spaces).
 */
struct fc_ils_gnf {			/* general name format */
	net8_t		gnf_len;	/* name length, a multiple of 4 */
	net8_t		_gnf_resvd[3];
	char		gnv_val[1];	/* name, possibly with zero fill */
};

#define	FC_ILS_GNF_LEN	5	/* expected length of structure */

/*
 * FC_ILS_ELP - exchange link parameters request or response payload.
 * We use rev 2 of the message.  The structure has rev 4 elements, as noted.
 */
#define	FC_ELP_REV 2		/* revision of ELP message */

struct fc_ils_elp {
	net32_t		elp_cmd;	/* command code (0x10000000) */
	net8_t		elp_rev;	/* revision */
	net8_t		elp_flags_h;	/* flags (not 16-bit aligned) */
	net8_t		elp_flags_l;	/* flags */
	net8_t		elp_bb_sc_n;	/* B-to_B state change number (rev 4) */
	net32_t		elp_r_a_tov;	/* R_A time out value required */
	net32_t		elp_e_d_tov;	/* E_D time out value required */
	net64_t		elp_port_wwn;
	net64_t		elp_switch_wwn;

	struct fc_elp_f_params {	/* class F parameters */
		net16_t		elpf_valid;	/* MSB is valid bit */
		net16_t		_elpf_res1;	/* reserved */
		net16_t		elpf_flags;	/* more flags */
		net16_t		elpf_rdf_size;	/* receive data field size */
		net16_t		elpf_con_seq;	/* concurrent sequences */
		net16_t		elpf_ee_cred;	/* end-to-end credits */
		net16_t		elpf_seq_exch;	/* sequences per exchange */
		net16_t		elpf_res;
	} elp_f_param;

	net16_t		elp_c1_flags;
	net16_t		elp_c1_rdf_size; /* class 1 receive data field size */
	net16_t		elp_c2_flags;
	net16_t		elp_c2_rdf_size; /* class 2 receive data field size */
	net16_t		elp_c3_flags;
	net16_t		elp_c3_rdf_size; /* class 3 receive data field size */
	net8_t		_elp_resvd[20];	/* reserved area */
	net16_t		elp_isl_flow_ctl_mode;	/* ISL flow control mode */
	net16_t		elp_fctl_parm_len;	/* parameter length */

	/*
	 * Flow control parameters follow.
	 */
};

#define	FC_ILS_ELP_F_PARAMS_LEN 16	/* expected length of struct */
#define	FC_ILS_ELP_LEN	(68 + FC_ILS_ELP_F_PARAMS_LEN)	/* expected len */

/*
 * elp_flags (as a 16-bit field).
 */
#define	FC_ELPF_BRIDGE	(1 << 15)	/* bridge (B) port */
#define	FC_ELPF_VFAB	(1 << 14)	/* B port supports virtual fabs (v4) */

/*
 * ELP Class parameters.
 */
#define	FC_ELP_CLASS_VALID	0x8000	/* class valid flag */
#define	FC_ELP_CLASS_SEQ	0x0800	/* switch can deliver sequentially */

#define	FC_ELP_DEF_RDF	2112		/* default receive data field size */

/*
 * ISL Flow Control modes (elp_isl_flow_ctl_mode)
 */
#define	FC_ELP_FCM_R_RDY	2
#define	FC_ELP_FCM_VC_RDY	0x2000	/* (not in rev 2) */

/*
 * R_RDY flow control parameter.
 */
struct fc_ils_elp_r_rdy {
	net32_t		rr_bb_credit;	/* buffer to buffer credits */
	net32_t		rr_bb_comp[4];	/* compatibility parameters */
};

#define	FC_ILS_ELP_R_RDY_LEN	20	/* expected length of struct */

/*
 * VC_RDY flow control parameter.
 */
struct fc_ils_elp_vc_rdy {
	net32_t		vcr_bb_cred;	/* buffer-to-buffer credit */
	net16_t		vcr_vc_scheme;	/* VC assignment scheme */
	net16_t		vcr_vc_value;	/* encodes number of VCs */
	net32_t		vcr_vc_cred[1];	/* per-VC credits (N of them) */
};

#define	FC_ILS_ELP_VC_RDY_LEN	12	/* expected length of struct */

#define	FC_ELP_VCRS_FIXED	1	/* fixed assignment scheme */
#define	FC_ELP_VCRS_VAR		2	/* variable assignment scheme */

#define	FC_ELP_VC_VAL_XXX	3	/* XXX fixed, 20 VCs for now */
#define	FC_ELP_VC_COUNT		20	/* number of VCs */

/*
 * FC_ILS_EFP exchange fabric parameters
 * The sequences in this exchange consist of EFP requests, followed by
 * domain ID list records and multicast ID list records.
 */
struct fc_ils_efp {
	net8_t		efp_cmd;	/* command code */
	net8_t		efp_rlen;	/* record length */
	net16_t		efp_plen;	/* payload length */
	net8_t		_efp_resvd[3];
	net8_t		efp_prin_swtch_prio;	/* principal switch priority */
	net64_t		efp_prin_swtch_wwn;	/* prin switch WWN */
};

#define	FC_ILS_EFP_LEN	    16	/* expected length of struct */

struct fc_ils_efp_rec {
	net8_t		efp_rec_type;	/* record type */
	net8_t		efp_domain_id;	/* domain ID */
	net8_t		_efp_resvd[6];
	net64_t		efp_dom_sw_wwn;
};

#define	FC_ILS_EFP_REC_LEN  16	/* expected length of struct */

struct fc_ils_mcast_id_rec {
	net8_t		efp_rec_type;	/* record type */
	net8_t		efp_group_id;	/* multicast group ID */
	net8_t		_efp_resvd[14];
};

#define	FC_ILS_MCAST_ID_REC_LEN 16	/* expected length of struct */

/*
 * Principle switch priorities:
 */
#define	FC_PRIN_PRI_HI		0x01	/* highest priority value */
#define	FC_PRIN_PRI_NOW		0x02	/* switch is currently the principal */
#define	FC_PRIN_PRI_NONE	0xff	/* incapable of being principal */

/*
 * EFP record types.
 */
#define	FC_EFP_REC_DID	    1		/* domain ID list record */
#define	FC_EFP_REC_MID	    2		/* multicast ID list record */

/*
 * FC_ILS_DIA domain ID assigned - request or payload.
 */
struct fc_ils_dia {
	net32_t		dia_cmd;	/* command code */
	net64_t		dia_wwn;	/* switch name */
	net8_t		_dia_resvd[4];	/* not meaningful */
};

#define	FC_ILS_DIA_LEN	    16		/* expected length of struct */

/*
 * FC_ILS_RDI request domain ID.
 */
struct fc_ils_rdi {
	net8_t		rdi_cmd;
	net8_t		_rdi_resvd;
	net16_t		rdi_len;	/* payload length */
	net64_t		rdi_sw_wwn;	/* requestor WWN */
	struct fc_ils_rdi_rec {
		net8_t	_rdi_resvd2[3];
		net8_t	rdi_did;
	} rdi_ils_rdi_rec[1];		/* N domain IDs. */
};

#define	FC_ILS_RDI_LEN	    16	/* expected length of struct */

/*
 * FSPF header.
 */
struct fc_ils_fspf {
	net8_t		fspf_cmd;	/* MSB of command */
	net8_t		fspf_cmd_resv[3]; /* always zero */

	net8_t		fspf_ver;	/* version */
	net8_t		_fspf_resv1;	/* obsolete */
	net8_t		fspf_auth_type;	/* authentication type */
	net8_t		_fspf_resv2;	/* reserved */

	net32_t		fspf_orig_did;	/* originating domain ID */
	net8_t		fspf_auth[8];	/* authentication */
};

#define	FC_ILS_FSPF_LEN     20	/* expected length of struct */

#define	FC_FSPF_VER    2	/* FSPF version */

/*
 * FC_ILS_HLO hello
 */
struct fc_ils_hlo {
	struct fc_ils_fspf hlo_fspf;	/* FSPF header */
	net32_t		_hlo_resvd;
	net32_t		hlo_hello_interval;
	net32_t		hlo_dead_interval;
	net32_t		hlo_recip_did;
	net8_t		_hlo_resvd2[1];
	net24_t		hlo_orig_port;	/* originating port index */
};

#define	FC_ILS_HLO_LEN	(FC_ILS_FSPF_LEN + 20)	/* expected length */

/*
 * FC_ILS_LSU link state update
 * FC_ILS_LSA link state announcement (same format)
 */
struct fc_ils_lsu {
	struct fc_ils_fspf lsu_fspf;
	net8_t		_lsu_resvd[3];
	net8_t		lsu_flags;
	net32_t		lsu_records;	/* number of LSRs to follow */
};

#define	FC_ILS_LSU_LEN	(FC_ILS_FSPF_LEN + 8)	/* expected length */

/*
 * lsu_flags.
 */
#define	FC_LSUF_DBE    0x01	/* data base exchange (if 0: topology update) */
#define	FC_LSUF_DBC    0x02	/* last sequence.  LSU contains no LSRS */

/*
 * Link state record.
 */
struct fc_ils_lsr {
	net8_t		lsr_type;	/* type (1 for switch) */
	net8_t		_lsr_resvd1;
	net16_t		lsr_age;	/* age (seconds) */
	net8_t		_lsr_resvd2[4];
	net32_t		lsr_id;		/* link state identifier */
	net32_t		lsr_adv_id;	/* advertising domain ID */
	net32_t		lsr_incarnation; /* LS incarnation number */
	net16_t		lsr_cksum;	/* checksum */
	net16_t		lsr_len;	/* overall length of LSR */
};

#define	FC_ILS_LSR_LEN	24	/* expected length */

#define	FC_FSPF_INC_START  0x80000001	/* starting LSR incarnation number */

/*
 * Link descriptor header.
 * Follows LSR in LSU.
 */
struct fc_ils_ldh {
	net8_t		_ldh_resvd[2];
	net16_t		ldh_links;	/* count of descs. to follow */
};


#define	FC_LSH_TYPE_SWITCH 1	/* switch link record */

/*
 * Link descriptor.
 */
struct fc_link_desc {
	net32_t		ld_link_id;	/* link ID (domain ID) */
	net8_t		_ld_resvd;
	net24_t		ld_output_port;	/* output port index */
	net8_t		_ld_resvd2;
	net24_t		ld_neighbor_port;	/* neighbor's port index */
	net8_t		ld_type;	/* link type */
	net8_t		_ld_resvd3;
	net16_t		ld_cost;	/* link cost */
};

#define	FC_LINK_DESC_LEN	16	/* expected length of struct */

#define	FC_LD_TYPE_PP		1	/* link type point-to-point */

/*
 * FC_ILS_MR merge request - merge zoning information
 * There are two versions, basic and enhanced.
 * The layout inside the payload is variable.
 */
struct fc_ils_mr {
	net8_t		mr_cmd;		/* command code 0x22 */
	net8_t		mr_proto;	/* protocol version */
	net8_t		mr_payload[1];	/* payload - variable layout */
};

/*
 * mr_proto.
 */
#define	FC_MR_BASIC		0	/* basic zoning */
#define	FC_MR_ENHANCED		1	/* enhnaced zoning mode */

struct fc_ils_mr_resp {			/* response to MR merge request */
	net32_t		mrr_sw_acc;	/* FC_ILS_SW_ACC << 24 */
	net8_t		_mrr_resvd[4];	/* reserved / obsolete */
};

/*
 * FC_ILS_ESC exchange switch capabilities
 */
struct fc_ils_esc {
	net8_t		esc_cmd;	/* command code 0x30 */
	net8_t		_esc_resvd;	/* reserved */
	net16_t		esc_len;	/* payload length */
	char		esc_vendor[8];	/* vendor ID string */
	struct fc_ils_proto {
		char		escp_vendor[8];	/* protocol vendor ID */
		char		_escp_resvd[2];
		net16_t		escp_prot_id;	/* protocol ID */
	} esc_proto[1];			/* more protocols may follow */
};

#define	FC_ILS_ESC_LEN	24	/* expected length of struct */

/*
 * escp_prot_id values.
 */
#define	FC_ESCP_FSPF_BB	1	/* FSPF backbone */
#define	FC_ESCP_FSPF	2	/* FSPF routing */

/*
 * FC_ILS_MRRA merge request resource alloc
 */
struct fc_ils_mrra {
	net8_t		mrra_cmd;	/* command code 0x34 */
	net8_t		_mrra_resvd[3];
	net32_t		mrra_rev;	/* revision */
	net32_t		mrra_size;	/* merge request size in words */
	char		mrra_vendor[8];	/* vendor defining next field */
	net8_t		mrra_vendor_info[8];	/* vendor-defined info */
};

#define	FC_ILS_MRRA_LEN	28	/* expected length of struct */

#define	FC_MRRA_REV	1	/* current revision of MRRA request */

/*
 * MRRA response payload.
 */
struct fc_ils_mrra_resp {
	net8_t		mrrr_cmd;	/* command code FC_ILS_SW_ACC */
	net8_t		_mrrr_resvd[3];
	char		mrrr_vendor[8];	/* vendor defining contents */
	net32_t		mrrr_resp;	/* response code */
	net32_t		mrrr_max;	/* max resources available (words) */
	net32_t		mrrr_retry;	/* retry time in sec (l.t. R_A_TOV) */
};

#define	FC_ILS_MRRA_RESP_LEN 24	/* expected length of struct */

/*
 * mrra_responses.
 */
#define	FC_MRRR_AVAIL	1		/* resources available */
#define	FC_MRRR_UNAV	2		/* resources unavailable */

#ifdef DEBUG_ASSERTS
/*
 * Static checks for packet structure sizes.
 * These catch some obvious errors in structure definitions.
 * This should generate no code.  The check should be true at compile time.
 */
static inline void fc_ils_size_checks(void)
{
	ASSERT_NOTIMPL(sizeof(struct fc_ils_sw_rjt) == FC_ILS_SW_RJT_LEN);
	ASSERT_NOTIMPL(sizeof(struct fc_ils_gnf) == FC_ILS_GNF_LEN);
	ASSERT_NOTIMPL(sizeof(struct fc_elp_f_params) ==
		       FC_ILS_ELP_F_PARAMS_LEN);
	ASSERT_NOTIMPL(sizeof(struct fc_ils_elp) == FC_ILS_ELP_LEN);
	ASSERT_NOTIMPL(sizeof(struct fc_ils_elp_r_rdy) == FC_ILS_ELP_R_RDY_LEN);
	ASSERT_NOTIMPL(sizeof(struct fc_ils_elp_vc_rdy) ==
		       FC_ILS_ELP_VC_RDY_LEN);
	ASSERT_NOTIMPL(sizeof(struct fc_ils_efp) == FC_ILS_EFP_LEN);
	ASSERT_NOTIMPL(sizeof(struct fc_ils_efp_rec) == FC_ILS_EFP_REC_LEN);
	ASSERT_NOTIMPL(sizeof(struct fc_ils_mcast_id_rec) ==
		       FC_ILS_MCAST_ID_REC_LEN);
	ASSERT_NOTIMPL(sizeof(struct fc_ils_dia) == FC_ILS_DIA_LEN);
	ASSERT_NOTIMPL(sizeof(struct fc_ils_rdi) == FC_ILS_RDI_LEN);
	ASSERT_NOTIMPL(sizeof(struct fc_ils_fspf) == FC_ILS_FSPF_LEN);
	ASSERT_NOTIMPL(sizeof(struct fc_ils_hlo) == FC_ILS_HLO_LEN);
	ASSERT_NOTIMPL(sizeof(struct fc_ils_lsu) == FC_ILS_LSU_LEN);
	ASSERT_NOTIMPL(sizeof(struct fc_ils_lsr) == FC_ILS_LSR_LEN);
	ASSERT_NOTIMPL(sizeof(struct fc_link_desc) == FC_LINK_DESC_LEN);
	ASSERT_NOTIMPL(sizeof(struct fc_ils_esc) == FC_ILS_ESC_LEN);
	ASSERT_NOTIMPL(sizeof(struct fc_ils_mrra) == FC_ILS_MRRA_LEN);
	ASSERT_NOTIMPL(sizeof(struct fc_ils_mrra_resp) == FC_ILS_MRRA_RESP_LEN);
}
#endif /* DEBUG_ASSERTS */

#endif /* _FC_ILS_H_ */
