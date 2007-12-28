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

#ifndef _FC_FCIP_H_
#define _FC_FCIP_H_

/*
 * Protocol definitions from RFC 3821 - Fibre Channel over IP.
 * Also see RFC 3643 - Fibre Channel Frame Encapsulation.
 *
 * Note:  The frame length field is the number of 32-bit words in
 * the encapsulation including the fcip_encaps_header, CRC and EOF words.
 * The minimum frame length value in bytes is (32 + 24 + 4 + 4) = 16.
 * The maximum frame length value in bytes is (32 + 24 + 2112 + 4 + 4) = 2172.
 */
#define FCIP_PROTO          1           /* current protocol number */
#define FCIP_VER            1           /* current version number */
#define FCIP_PORT           3225        /* well known port for FCIP */
#define FCIP_MIN_FRAME_LEN  64          /* min frame len (bytes) (see above) */
#define FCIP_MAX_PAYLOAD    2112        /* max payload length in bytes */
#define FCIP_MAX_FRAME_LEN  (FCIP_MIN_FRAME_LEN + FCIP_MAX_PAYLOAD)

struct fcip_encaps_hdr {
    u_int32_t   fcip_proto_ver;
    u_int32_t   fcip_proto_ver_c;       /* copy of protocol, version */

    u_int32_t   fcip_pflags_word;       /* only first byte is pflags */

    u_int16_t   fcip_len_flags;         /* 10-bit length/4 w/ 6 flag bits */
    u_int16_t   fcip_len_flags_n;

    /*
     * Offset 0x10
     */
    u_int32_t   fcip_time[2];           /* integer and fraction */
    u_int32_t   fcip_crc;               /* CRC - reserved in FCIP - zero */

    u_int32_t    fcip_sof;              /* SOF word including ones comp. */

    /* 0x20 - FC frame content followed by EOF word */
};

#define FCIP_ENCAPS_HDR_LEN 0x20        /* expected length for asserts */

/*
 * Macro's for making redundant copies of flags and protocol / version
 */
#define FCIP_XY(x, y)   ((((x) & 0xff) << 8) | ((y) & 0xff))
#define FCIP_XYXY(x, y) ((FCIP_XY(x, y) << 16) | FCIP_XY(x, y))
#define FCIP_XYNN(x, y) htonl(FCIP_XYXY(x, y) ^ 0xffff)

#define FCIP_SOF(n)     FCIP_XYNN(n, n)        /* start of frame */
#define FCIP_EOF(n)     FCIP_XYNN(n, n)
#define FCIP_PFLAGS(n)  FCIP_XYNN(n, 0)
#define FCIP_PROTO_VER  FCIP_XYNN(FCIP_PROTO, FCIP_VER)

#define FCIP_WORD_ERROR(x) ((((x) >> 16) & 0xffff) != (~(x) & 0xffff))

#define FCIP_DECAPS_SOF(n)  ((ntohl(n) >> 24) & 0xff)
#define FCIP_DECAPS_EOF(n)  ((ntohl(n) >> 24) & 0xff)

/*
 * fcip_pflags.
 */
#define FCIP_PF_CH      0x80        /* changed bit */
#define FCIP_PF_SF      0x01        /* special frame */

#define FCIP_WWN_LEN    8           /* size of world-wide-name */
#define FCIP_EID_LEN    8           /* size of entity name */

/*
 * Special frame format.
 */
struct fcip_fsf {
    struct fcip_encaps_hdr fsf_encaps;  /* header with FCIP_SOF(0) */

    /*
     * Offset 0x20
     */
    net64_t     fsf_src_wwn;        /* source world wide name */
    net64_t     fsf_src_eid;        /* source entity ID */

    /*
     * 0x30 (word 12)
     */
    u_int32_t   fsf_nonce[2];       /* 64-bit connection uniquifier */
    u_int8_t    fsf_cflags;         /* connection usage flags */
    u_int8_t    _fsf_res39;         /* reserved */
    u_int16_t   fsf_conn_usage;     /* conn usage code (zero) */

    /*
     * 0x3c
     */
    net64_t     fsf_dest_wwn;
    u_int32_t   fsf_k_a_tov;        /* time out value */

    /*
     * 0x48
     */
    u_int32_t   fsf_eof;            /* reserved (in lieu of EOF) */

    /*
     * 0x4c
     */
};

/*
 * fcip_cflags - connection usage flags
 */
#define FCIP_CUSAGE_SOFf    0x80    /* carry SOFf frames */
#define FCIP_CUSAGE_SOF2    0x40    /* carry SOFi2 and SOFn2 frames */
#define FCIP_CUSAGE_SOF3    0x20    /* carry SOFi3 and SOFn3 frames */
#define FCIP_CUSAGE_SOF4    0x10    /* carry SOFi4/n4/c4 frames */

#endif /* _FC_FCIP_H_ */
