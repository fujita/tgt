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

#ifndef _FC_FC2_H_
#define _FC_FC2_H_

/*
 * Fibre Channel Exchanges and Sequences.
 */
#ifndef PACKED
#define PACKED  __attribute__ ((__packed__))
#endif /* PACKED */


/*
 * Sequence Status Block.
 * This format is set by the FC-FS standard and is sent over the wire.
 * Note that the fields aren't all naturally aligned.
 */
struct fc_ssb {
    u_int8_t    ssb_seq_id;             /* sequence ID */
    u_int8_t    _ssb_resvd;
    u_int16_t   ssb_low_seq_cnt;        /* lowest SEQ_CNT */

    u_int16_t   ssb_high_seq_cnt;       /* highest SEQ_CNT */
    u_int16_t   ssb_s_stat;             /* sequence status flags */

    u_int16_t   ssb_err_seq_cnt;        /* error SEQ_CNT */
    u_int8_t    ssb_fh_cs_ctl;          /* frame header CS_CTL */
    u_int16_t   ssb_fh_ox_id;           /* frame header OX_ID */
    u_int16_t   ssb_rx_id;              /* responder's exchange ID */
    u_int8_t    _ssb_resvd2[2];
} PACKED;

/*
 * The SSB should be 17 bytes.  Since it's layout is somewhat strange,
 * we define the size here so that code can ASSERT that the size comes out
 * correct.
 */
#define FC_SSB_SIZE         17          /* length of fc_ssb for assert */

/*
 * ssb_s_stat - flags from FC-FS-2 T11/1619-D Rev 0.90.
 */
#define SSB_ST_RESP         (1 << 15)   /* sequence responder */
#define SSB_ST_ACTIVE       (1 << 14)   /* sequence is active */
#define SSB_ST_ABNORMAL     (1 << 12)   /* abnormal ending condition */

#define SSB_ST_REQ_MASK     (3 << 10)   /* ACK, abort sequence condition */
#define SSB_ST_REQ_CONT     (0 << 10)
#define SSB_ST_REQ_ABORT    (1 << 10)
#define SSB_ST_REQ_STOP     (2 << 10)
#define SSB_ST_REQ_RETRANS  (3 << 10)

#define SSB_ST_ABTS         (1 << 9)    /* ABTS protocol completed */
#define SSB_ST_RETRANS      (1 << 8)    /* retransmission completed */
#define SSB_ST_TIMEOUT      (1 << 7)    /* sequence timed out by recipient */
#define SSB_ST_P_RJT        (1 << 6)    /* P_RJT transmitted */

#define SSB_ST_CLASS_BIT    4           /* class of service field LSB */
#define SSB_ST_CLASS_MASK   3           /* class of service mask */
#define SSB_ST_ACK          (1 << 3)    /* ACK (EOFt or EOFdt) transmitted */

/*
 * Exchange Status Block.
 * This format is set by the FC-FS standard and is sent over the wire.
 * Note that the fields aren't all naturally aligned.
 */
struct fc_esb {
    u_int8_t    esb_cs_ctl;             /* CS_CTL for frame header */
    u_int16_t   esb_ox_id;              /* originator exchange ID */
    u_int16_t   esb_rx_id;              /* responder exchange ID */
    u_int32_t   esb_orig_fid;           /* fabric ID of originator */
    u_int32_t   esb_resp_fid;           /* fabric ID of responder */
    u_int32_t   esb_e_stat;             /* status */
    u_int8_t    _esb_resvd[4];
    u_int8_t    esb_service_params[112]; /* TBD */
    u_int8_t    esb_seq_status[8];      /* sequence statuses, 8 bytes each */
} PACKED;


/*
 * Define expected size for ASSERTs.
 * See comments on FC_SSB_SIZE.
 */
#define FC_ESB_SIZE         (1 + 5*4 + 112 + 8)     /* expected size */

/*
 * esb_e_stat - flags from FC-FS-2 T11/1619-D Rev 0.90.
 */
#define ESB_ST_RESP         (1 << 31)   /* responder to exchange */
#define ESB_ST_SEQ_INIT     (1 << 30)   /* port holds sequence initiaive */
#define ESB_ST_COMPLETE     (1 << 29)   /* exchange is complete */
#define ESB_ST_ABNORMAL     (1 << 28)   /* abnormal ending condition */
#define ESB_ST_REC_QUAL     (1 << 26)   /* recovery qualifier active */

#define ESB_ST_ERRP_BIT     24          /* LSB for error policy */
#define ESB_ST_ERRP_MASK    (3 << 24)   /* mask for error policy */
#define ESB_ST_ERRP_MULT    (0 << 24)   /* abort, discard multiple sequences */
#define ESB_ST_ERRP_SING    (1 << 24)   /* abort, discard single sequence */
#define ESB_ST_ERRP_INF     (2 << 24)   /* process with infinite buffers */
#define ESB_ST_ERRP_IMM     (3 << 24)   /* discard mult. with immed. retran. */

#define ESB_ST_OX_ID_INVL   (1 << 23)   /* originator XID invalid */
#define ESB_ST_RX_ID_INVL   (1 << 22)   /* responder XID invalid */
#define ESB_ST_PRI_INUSE    (1 << 21)   /* priority / preemption in use */

#endif /* _FC_FC2_H_ */
