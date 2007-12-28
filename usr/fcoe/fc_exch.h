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

#ifndef _LIBFC_EXCH_H_
#define _LIBFC_EXCH_H_

/*
 * Fibre Channel Exchanges and Sequences - software interface.
 * Function definitions for managing Fibre Channel Exchanges and Sequences.
 */
#include "fc_event.h"
#include "fc_fs.h"
#include "fc_els.h"

/*
 * Principles of Operation.
 *
 * This exchange manager is intended to be used by an N port or set of N ports.
 * The N port involved could be an internal service on a switch, such as the
 * fabric manager or directory server.
 *
 * The exchange manager instance is created by calling fc_exch_mgr_alloc().
 * The returned pointer is then used to create exchanges and sequences.
 *
 * As FC frames arrive on the port, they should be passed to fc_exch_mgr_recv(),
 * which will look up the exchange and call the appropriate receive handler.
 * For new exchanges the receive handler will be the one for the local port.
 * For exchanges initiated by this exchange manager, the receive handler
 * is set when the exchange is created.
 *
 * To send a FC frame as part of a sequence, the client must allocate the
 * sequence, fill in the payload, and then send the frame.
 * Each of these steps is described below and uses fc_seq_* interfaces.
 *
 * The sequence should be allocated by calling either fc_seq_start_exch(),
 * which creates a new exchange and initial sequence, or fc_seq_start(),
 * which creates a sequence on an existing exchange.
 *
 * The frame is sent by calling one of three functions.  Use fc_seq_send_last(),
 * for the final sequence of an exchange.  Use fc_seq_send_req() if sequence
 * initiative is to be transferred.  Otherwise, use fc_seq_send().
 */

struct fc_exch_mgr;
struct fc_exch;
struct fc_frame;
struct fc_seq;
struct fc_sess;
struct fc_local_port;
struct fc_port;

#define FC_EXCH_POOLS       32	/* limit on number of "per-CPU" pools */

/*
 * Allocate an exchange manager.
 */
struct fc_exch_mgr *fc_exch_mgr_alloc(enum fc_class,
				      fc_xid_t min_xid, fc_xid_t max_xid);

/*
 * Free an exchange manager.
 */
void fc_exch_mgr_free(struct fc_exch_mgr *);

/*
 * Reset an exchange manager, completing all sequences and exchanges.
 * If s_id is non-zero, reset only exchanges originating from that FID.
 * If d_id is non-zero, reset only exchanges sending to that FID.
 */
void fc_exch_mgr_reset(struct fc_exch_mgr *, fc_fid_t s_id, fc_fid_t d_id);

/*
 * Set addresses for the exchange of a sequence.
 * Note this must be done before the first sequence of the exchange is sent.
 */
void fc_exch_set_addr(struct fc_exch *, fc_fid_t orig, fc_fid_t resp);

/*
 * Set the output port to be used for an exchange.
 */
void fc_exch_set_port(struct fc_exch *, struct fc_port *);

/*
 * Start a new sequence as originator on a new exchange.
 */
struct fc_seq *fc_seq_start_exch(struct fc_exch_mgr *,
				 void (*recv) (struct fc_seq *,
					       struct fc_frame *, void *),
				 void (*errh) (enum fc_event, void *),
				 void *arg, fc_fid_t sid, fc_fid_t did);

/*
 * Start a new sequence on an existing exchange.
 */
struct fc_seq *fc_seq_start(struct fc_exch *);

/*
 * Start a new sequence on the same exchange as the supplied sequence.
 */
struct fc_seq *fc_seq_start_next(struct fc_seq *);

/*
 * Start a new sequence on the same exchange as the supplied sequence
 * set the f_ctl of the new sequence.
 */
struct fc_seq *fc_seq_start_next_fctl(struct fc_seq *, u_int32_t);

void fc_seq_hold(struct fc_seq *);
void fc_seq_release(struct fc_seq *);

/*
 * Set a timer on an exchange.
 * The time is a minimum delay in milliseconds until the timer fires.
 */
void fc_exch_timer_set(struct fc_exch *ep, u_int timer_msec);

/*
 * Get the exchange for a sequence.
 */
struct fc_exch *fc_seq_exch(const struct fc_seq *);

/*
 * Abort the exchange used by the given sequence.
 */
int fc_seq_abort_exch(const struct fc_seq *);

/*
 * Set addresses for the exchange of a sequence.
 * Note this must be done before the first sequence of the exchange is sent.
 * Usually this is for well known ports.
 */
void fc_seq_set_addr(struct fc_seq *, fc_fid_t orig_fid, fc_fid_t resp_fid);

/*
 * Set the receive handler and arg for the exchange of an existing sequence.
 */
void fc_seq_set_recv(struct fc_seq *,
			 void (*recv)(struct fc_seq *,
					struct fc_frame *, void *),
			 void *arg);

/*
 * Send a frame for a sequence.
 * Marks sequence complete (perhaps pending ACK).
 * Caller must use fc_frame_setup() first to set r_ctl and type.
 */
int fc_seq_send(struct fc_seq *, struct fc_frame *);

/*
 * Send a frame for a sequence where more frames will follow.
 */
int fc_seq_send_frag(struct fc_seq *, struct fc_frame *);

/*
 * Send a frame for a sequence, which is also the last sequence in the exchange.
 * Also marks sequence and exchange complete (perhaps pending ACK).
 */
int fc_seq_send_last(struct fc_seq *, struct fc_frame *,
		     enum fc_rctl, enum fc_fh_type);

/*
 * Send a frame for a sequence with transfer of sequence initiative.
 * Also marks sequence as complete (perhaps pending ACK).
 */
int fc_seq_send_tsi(struct fc_seq *, struct fc_frame *);

/*
 * Send a frame for a sequence with transfer of sequence initiative.
 * Also marks sequence as complete (perhaps pending ACK).
 */
int fc_seq_send_req(struct fc_seq *, struct fc_frame *,
		    enum fc_rctl, enum fc_fh_type, u_int32_t offset);

/*
 * Send a frame for the next sequence on the same exchange.
 * Also transfers sequence initiative.
 */
int fc_seq_send_next_req(struct fc_seq *, struct fc_frame *);

/*
 * Mark exchange complete (pending all sequences complete).
 * Doesn't affect any holds on the exchange.
 */
void fc_exch_complete(struct fc_exch *);

/*
 * Mark sequence complete (pending ACKs if any expected).
 * Doesn't affect any holds on the exchange.
 */
void fc_seq_complete(struct fc_seq *);

/*
 * Mark sequence complete (pending ACKs if any expected).
 * Drops a hold on the sequence.
 * Doesn't affect any holds on the exchange.
 */
void fc_seq_exch_complete(struct fc_seq *);

/*
 * Get maximum payload size for a sequence.
 */
size_t fc_seq_mfs(struct fc_seq *);

/*
 * Handle receive where the other end is originating the sequence and exchange.
 */
void fc_exch_recv_req(struct fc_exch_mgr *, struct fc_frame *, size_t payload,
		      void (*dflt_recv)(struct fc_seq *,
					struct fc_frame *, void *),
		      void *);

/*
 * Handle receive where the other end is originating the sequence in
 * response to our exchange.
 */
void fc_exch_recv_seq_resp(struct fc_exch_mgr *, struct fc_frame *);

/*
 * Handle receive of a response to our sequence.
 */
void fc_exch_recv_resp(struct fc_exch_mgr *, struct fc_frame *);

/*
 * Send an ELS LS_ACC or LS_RJT frame.
 */
void fc_seq_ls_acc(struct fc_seq *);
void fc_seq_ls_rjt(struct fc_seq *, enum fc_els_rjt_reason,
		   enum fc_els_rjt_explan);

/*
 * Send an ELS_REC (read exchange concise) inquiring about a sequence.
 */
struct fc_seq *fc_seq_rec_req(struct fc_seq *inq_sp,
		void (*recv)(struct fc_seq *, struct fc_frame *, void *),
		void (*errh)(enum fc_event, void *), void *arg);

/*
 * kernel module setup and teardown functions.
 */
void fc_exch_module_init(void);
void fc_exch_module_exit(void);

#endif /* _LIBFC_EXCH_H_ */
