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

#ifndef _FC_FRAME_H_
#define _FC_FRAME_H_

/*
 * The fc_frame interface is used to pass frame data between functions.
 * The frame includes the data buffer, length, and SOF / EOF delimiter types.
 * A pointer to the port structure of the receiving port is also includeded.
 */

#include "fc_fs.h"
#include "fc_encaps.h"
#include "fc_port.h"

#define	FC_FRAME_HEADROOM	32	/* headroom for VLAN + FCoE headers */
#define	FC_FRAME_TAILROOM	8	/* trailer space for FCoE */

struct fc_frame {
	struct fc_port	*fr_in_port;	/* port where frame was received */
	struct fc_seq	*fr_seq;	/* for use with exchange manager */
	struct fc_frame_header *fr_hdr;	/* pointer to frame header in buffer */
	const char	*fr_stamp;	/* debug info on last usage */
	void		(*fr_free)(struct fc_frame *); /* free callback */
	void		*fr_free_priv;	/* private data for free handler */
	enum fc_sof	fr_sof;		/* start of frame delimiter */
	enum fc_eof	fr_eof;		/* end of frame delimiter */
	u_int16_t	fr_len;		/* total length including S/G bytes */
	u_int8_t	fr_flags;	/* flags - see below */
	void		(*fr_destructor)(void *); /* destructor for frame */
	void		*fr_arg;                  /* arg for destructor */
};

/*
 * fr_flags.
 */
#define	FCPHF_CRC_UNCHECKED	0x01	/* CRC not computed, still appended */
#define	FCPHF_STATIC		0x02	/* frame not dynamicly allocated */
#define	FCPHF_FREED		0x04	/* frame free routine has been called */

/*
 * Add a "stamp" indicating where a frame was last used.
 */
#ifdef FC_FRAME_DEBUG
#define FC_FRAME_STAMP(fp)  (fp)->fr_stamp = __FUNCTION__
#else
#define FC_FRAME_STAMP(fp)
#endif /* FC_FRAME_DEBUG */

/*
 * Initialize a frame.
 * We don't do a complete memset here for performance reasons.
 * The caller must set fr_free, fr_hdr, fr_len, fr_sof, and fr_eof eventually.
 */
static inline void fc_frame_init(struct fc_frame *fp)
{
	fp->fr_in_port = NULL;
	fp->fr_seq = NULL;
	fp->fr_flags = 0;
	FC_FRAME_STAMP(fp);
}

extern void fc_frame_free_static(struct fc_frame *);

/*
 * Initialize a frame that is staticly allocated.
 */
static inline void fc_frame_init_static(struct fc_frame *fp)
{
	fc_frame_init(fp);
	FC_FRAME_STAMP(fp);
	fp->fr_free = fc_frame_free_static;
	fp->fr_flags = FCPHF_STATIC;
}

/*
 * Test that an staticly-allocated frame has been freed.
 */
static inline int fc_frame_freed_static(struct fc_frame *fp)
{
	return (fp->fr_flags & FCPHF_FREED);
}

/*
 * Allocate fc_frame structure and buffer.  Set the initial length to
 * payload_size + sizeof (struct fc_frame_header).
 */
struct fc_frame *fc_frame_alloc_int(size_t payload_size);

struct fc_frame *fc_frame_alloc_fill(struct fc_port *, size_t payload_len);

/*
 * Get frame for sending via port.
 */
static inline struct fc_frame *fc_port_frame_alloc(struct fc_port *port,
	size_t payload_len)
{
	return (*port->np_frame_alloc)(payload_len);
}

static inline struct fc_frame *fc_frame_alloc_inline(struct fc_port *port,
		size_t len, const char *stamp)
{
	struct fc_frame *fp;

	/*
	 * Note: Since len will often be a constant multiple of 4,
	 * this check will usually be evaluated and eliminated at compile time.
	 */
	if ((len % 4) != 0)
		fp = fc_frame_alloc_fill(port, len);
	else
		fp = fc_port_frame_alloc(port, len);
#ifdef FC_FRAME_DEBUG
	if (fp)
		fp->fr_stamp = stamp;
#endif /* FC_FRAME_DEBUG */
	return (fp);
}

/*
 * Allocate fc_frame structure and buffer.  Set the initial length to
 * payload_size + sizeof (struct fc_frame_header).
 * This version of fc_frame_alloc() stamps the frame to help find leaks.
 */
#define fc_frame_alloc(port, len) \
	fc_frame_alloc_inline(port, len, __FUNCTION__)
/*
 * Free the fc_frame structure and buffer.
 */
static inline void fc_frame_free(struct fc_frame *fp)
{
	FC_FRAME_STAMP(fp);
	fp->fr_hdr = NULL;
	(*fp->fr_free)(fp);
}

/*
 * Get frame header from message in fc_frame structure.
 * This hides a cast and provides a place to add some checking.
 */
static inline struct fc_frame_header *fc_frame_header_get(const struct
							  fc_frame *fp)
{
	return fp->fr_hdr;
}

/*
 * Get frame payload from message in fc_frame structure.
 * This hides a cast and provides a place to add some checking.
 * The len parameter is the minimum length for the payload portion.
 * Returns NULL if the frame is too short.
 *
 * This assumes the interesting part of the payload is in the first part
 * of the buffer for received data.  This may not be appropriate to use for
 * buffers being transmitted.
 */
static inline void *fc_frame_payload_get(const struct fc_frame *fp,
					 size_t len)
{
	void *pp = NULL;

	if (fp->fr_len >= sizeof(struct fc_frame_header) + len)
		pp = fc_frame_header_get(fp) + 1;
	return pp;
}

/*
 * Get frame payload opcode (first byte) from message in fc_frame structure.
 * This hides a cast and provides a place to add some checking.
 */
static inline u_char fc_frame_payload_op(const struct fc_frame *fp)
{
	return *(u_char *) fc_frame_payload_get(fp, sizeof(u_char));
}

/*
 * Get FC class from frame.
 */
static inline enum fc_class fc_frame_class(const struct fc_frame *fp)
{
	return fc_sof_class(fp->fr_sof);
}

/*
 * Set r_ctl and type in preparation for sending frame.
 * This also clears fh_parm_offset.
 */
static inline void fc_frame_setup(struct fc_frame *fp, enum fc_rctl r_ctl,
				  enum fc_fh_type type)
{
	struct fc_frame_header *fh;

	fh = fc_frame_header_get(fp);
	fh->fh_r_ctl = r_ctl;
	fh->fh_type = type;
	net32_put(&fh->fh_parm_offset, 0);
}

/*
 * Set offset in preparation for sending frame.
 */
static inline void
fc_frame_set_offset(struct fc_frame *fp, u_int32_t offset)
{
	struct fc_frame_header *fh;

	fh = fc_frame_header_get(fp);
	net32_put(&fh->fh_parm_offset, offset);
}

#endif /* _FC_FRAME_H_ */
