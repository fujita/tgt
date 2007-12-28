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

/*
 * Fibre Channel exchange and sequence handling.
 */

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <linux/if.h>

#include "list.h"
#include "log.h"
#include "util.h"

#include "net_types.h"
#include "sa_hash.h"
#include "sa_timer.h"

#include "fc_fcip.h"
#include "fc_fc2.h"
#include "fc_fs.h"
#include "fc_ils.h"
#include "fc_els.h"

#include "fc_types.h"
#include "fc_event.h"
#include "fc_frame.h"
#include "fc_exch.h"
#include "fc_port.h"
#include "fc_exch_impl.h"

#include "fcdev.h"

/*
 * fc_exch_debug can be set in debugger or at compile time to get more logs.
 */
static int fc_exch_debug;

static void fc_seq_fill_hdr(struct fc_seq *, struct fc_frame *);

static void fc_exch_hold(struct fc_exch *);
static void fc_exch_release(struct fc_exch *);
static void fc_exch_complete_locked(struct fc_exch *);
static void fc_exch_timeout(void *);

/*
 * Internal implementation notes.
 *
 * See libfc/fc_exch.h for an overview on usage of this interface.
 * See exch_impl.h for notes on the data structures.
 *
 * The exchange manager is now per-session.
 * The sequence manager is one per exchange manager
 * and currently never separated.
 *
 * Section 9.8 in FC-FS-2 specifies:  "The SEQ_ID is a one-byte field
 * assigned by the Sequence Initiator that shall be unique for a specific
 * D_ID and S_ID pair while the Sequence is open."   Note that it isn't
 * qualified by exchange ID, which one might think it would be.
 * In practice this limits the number of open sequences and exchanges to 256
 * per session.  For most targets we could treat this limit as per exchange.
 *
 * Exchanges aren't currently timed out.  The exchange is freed when the last
 * sequence is received and all sequences are freed.  It's possible for the
 * remote port to leave an exchange open without sending any sequences.
 *
 * Notes on reference counts:
 *
 * Sequences and exchanges are reference counted and they get freed when
 * the reference count becomes zero.  Sequences hold reference counts on
 * the associated exchange.  Sequences can be freed only if their
 * seq_active flag is not set and their reference count has gone to zero.
 *
 * When calling a receive routine on a sequence for an incoming request or
 * response, the sequence is held by the caller and shouldn't be released
 * in the receive handler.
 *
 * Timeouts:
 * Sequences are timed out for E_D_TOV and R_A_TOV.
 *
 * Sequence event handling:
 *
 * The following events may occur on initiator sequences:
 *
 *      Send.
 *          For now, the whole thing is sent.
 *      Receive ACK
 *          This applies only to class F.
 *          The sequence is marked complete.
 *      ULP completion.
 *          The upper layer calls fc_seq_complete() or fc_seq_exch_complete().
 *          If anything's been sent, we still need to wait for the ACK (class F)
 *          before retiring the sequence ID, and the last sequence on the
 *          exchange.
 *      RX-inferred completion.
 *          When we receive the next sequence on the same exchange, we can
 *          retire the previous sequence ID.  (XXX not implemented).
 *      Timeout.
 *          R_A_TOV frees the sequence ID.  If we're waiting for ACK,
 *          E_D_TOV causes abort and retransmission?  XXX defer.
 *      Receive RJT
 *          XXX defer.
 *      Send ABTS
 *          On timeout.  XXX defer.
 *
 * The following events may occur on recipient sequences:
 *
 *      Receive
 *          Allocate sequence for first frame received.
 *          Hold during receive handler.
 *          Release when final frame received.
 *          Keep status of last N of these for the ELS RES command.  XXX TBD.
 *      Receive ABTS
 *          Deallocate sequence
 *      Send RJT
 *          Deallocate
 *
 * For now, we neglect conditions where only part of a sequence was
 * received or transmitted, or where out-of-order receipt is detected.
 */

/*
 * Locking notes:
 *
 * In the user-level code, we're single threaded, running in a select loop.
 * In kernel level, we run in a per-CPU worker thread (XXX what's correct term?)
 *
 * To protect against concurrency between a worker thread code and timers,
 * sequence allocation and deallocation must be locked.
 *  - sequence refcnt can be done atomicly without locks.
 *  - allocation / deallocation can be in an per-exchange lock.
 */

/*
 * Setup memory allocation pools shared by all exchange managers.
 */
void fc_exch_module_init(void)
{
}

/*
 * Free memory allocation pools shared by all exchange managers.
 */
void fc_exch_module_exit(void)
{
}

/*
 * opcode names for debugging.
 */
static char *fc_exch_rctl_names[] = FC_RCTL_NAMES_INIT;

#define FC_TABLE_SIZE(x)   (sizeof (x) / sizeof (x[0]))

static inline const char *fc_exch_name_lookup(u_int op, char **table,
					      u_int max_index)
{
	const char *name = NULL;

	if (op < max_index)
		name = table[op];
	if (!name)
		name = "unknown";
	return name;
}

static const char *fc_exch_rctl_name(u_int op)
{
	return fc_exch_name_lookup(op, fc_exch_rctl_names,
				   FC_TABLE_SIZE(fc_exch_rctl_names));
}

/*
 * Initialize an exchange manager.
 * Returns non-zero on allocation errors.
 */
static int fc_exch_mgr_init(struct fc_exch_mgr *mp, enum fc_class class,
			    fc_xid_t min_xid, fc_xid_t max_xid)
{
	fc_xid_t xid;
	struct fc_exch *ep;
	struct fc_exch_pool *pp;
	u_int pool;
	u_int pool_count;

	mp->em_class = class;

	/*
	 * Initialize per-CPU free lists.
	 */
	pool_count = 1;

	/*
	 * Make min_xid hash to the first pool, and max_xid to the last, by
	 * increasing min_xid, and decreasing max_xid, respectively.
	 * Otherwise, the hash will be non-optimal and there may be some
	 * unused and uninitialized exchanges that fc_exch_lookup() would find.
	 */
	min_xid = (min_xid + (pool_count - 1)) & ~(pool_count - 1);
	max_xid = (max_xid - (pool_count - 1)) | (pool_count - 1);
	mp->em_min_xid = min_xid;
	mp->em_max_xid = max_xid;

	for (pool = 0; pool < pool_count; pool++) {
		pp = &mp->em_pool[pool];
		pp->emp_mgr = mp;
		pp->emp_exch_in_use = 0;
		INIT_LIST_HEAD(&pp->emp_exch_busy);
		INIT_LIST_HEAD(&pp->emp_exch_free);

		/*
		 * Initialize exchanges for the pool.
		 */
		for (xid = min_xid + pool; xid <= max_xid;
		     xid += (fc_xid_t) pool_count) {

			ep = &mp->em_exch[xid - min_xid];
			ep->ex_pool = pp;
			ep->ex_xid = xid;
			ep->ex_e_stat = ESB_ST_COMPLETE;
			sa_timer_init(&ep->ex_timer, fc_exch_timeout, ep);
			list_add_tail(&ep->ex_list, &pp->emp_exch_free);
			pp->emp_exch_total++;
		}
	}
	return (0);
}

/*
 * Allocate an exchange manager.
 */
struct fc_exch_mgr *fc_exch_mgr_alloc(enum fc_class class,
				      fc_xid_t min_xid, fc_xid_t max_xid)
{
	struct fc_exch_mgr *mp;
	size_t len;

	if (!min_xid)
		min_xid++;
	len = (max_xid + 1 - min_xid) * sizeof(struct fc_exch) + sizeof(*mp);
	mp = (struct fc_exch_mgr *)zalloc(len);
	if (mp) {
		if (fc_exch_mgr_init(mp, class, min_xid, max_xid) != 0) {
			fc_exch_mgr_free(mp);
			mp = NULL;
		}
	}
	return mp;
}

/*
 * Free an exchange manager.
 * This is also used to recover from unsuccessful allocations.
 */
void fc_exch_mgr_free(struct fc_exch_mgr *mp)
{
	free(mp);
}

/*
 * Find an exchange.
 */
static inline struct fc_exch *fc_exch_lookup(struct fc_exch_mgr *mp,
					     fc_xid_t xid)
{
	struct fc_exch *ep = NULL;

	if (xid >= mp->em_min_xid && xid <= mp->em_max_xid) {
		ep = &mp->em_exch[xid - mp->em_min_xid];
		if (ep->ex_refcnt == 0 &&
		    (ep->ex_e_stat & ESB_ST_COMPLETE)) {
			ep = NULL;	/* exchange is free */
		}
	}
	return ep;
}

/*
 * Hold an exchange - keep it from being freed.
 */
static void fc_exch_hold(struct fc_exch *ep)
{
	ep->ex_refcnt++;
}

/*
 * Release a reference to an exchange.
 * If the refcnt goes to zero and the exchange is complete, it is freed.
 */
static void fc_exch_release(struct fc_exch *ep)
{
	struct fc_exch_pool *pp;

	if (!(--ep->ex_refcnt) &&
	    (ep->ex_e_stat & ESB_ST_COMPLETE)) {
		sa_timer_cancel(&ep->ex_timer);
		pp = ep->ex_pool;
		pp->emp_exch_in_use--;
		list_del(&ep->ex_list);
		list_add_tail(&ep->ex_list, &pp->emp_exch_free);
	}
}

/*
 * Get the exchange for a sequence.
 * This would use container_of() but it isn't defined outside of the kernel.
 */
inline struct fc_exch *fc_seq_exch(const struct fc_seq *sp)
{
	return (struct fc_exch *)
	    ((char *)sp - offsetof(struct fc_exch, ex_seq));
}

/*
 * Hold a sequence - keep it from being freed.
 */
inline void fc_seq_hold(struct fc_seq *sp)
{
	sp->seq_refcnt++;
}

/*
 * Allocate a sequence.
 *
 * We don't support multiple originated sequences on the same exchange.
 * By implication, any previously originated sequence on this exchange
 * is complete, and we reallocate the same sequence.
 */
static struct fc_seq *fc_seq_alloc(struct fc_exch *ep, u_int8_t seq_id)
{
	struct fc_seq *sp;

	sp = &ep->ex_seq;
	if (sp->seq_refcnt == 0 && sp->seq_active == 0)
		fc_exch_hold(ep);	/* hold exchange for the sequence */
	sp->seq_active = 0;
	sp->seq_s_stat = 0;
	sp->seq_f_ctl = 0;
	sp->seq_cnt = 0;
	sp->seq_id = seq_id;
	fc_seq_hold(sp);
	return (sp);
}

/*
 * Release a sequence.
 */
void fc_seq_release(struct fc_seq *sp)
{
	if (!(--sp->seq_refcnt) && !sp->seq_active)
		fc_exch_release(fc_seq_exch(sp));
}

/*
 * Mark sequence complete.
 * The sequence may or may not have been active prior to this call.
 * The caller must hold the sequence and that hold is not released.
 */
inline void fc_seq_complete(struct fc_seq *sp)
{
	sp->seq_active = 0;
}

/*
 * Exchange timeout - handle exchange timer expiration.
 * The timer will have been cancelled before this is called.
 */
static void fc_exch_timeout(void *ep_arg)
{
	struct fc_exch *ep = ep_arg;
	struct fc_seq *sp = &ep->ex_seq;
	void (*errh) (enum fc_event, void *);
	void *arg;

	fc_seq_hold(sp);
	if (ep->ex_aborted) {
		fc_seq_exch_complete(sp);
	} else {
		errh = ep->ex_errh;
		arg = ep->ex_recv_arg;
		ep->ex_aborted = 1;
		fc_seq_complete(sp);
		fc_exch_timer_set(ep, FC_DEF_R_A_TOV);
		fc_seq_abort_exch(sp);
		if (errh)
			(*errh) (FC_EV_TIMEOUT, arg);
		fc_seq_release(sp);
	}
}

/*
 * Set timer for an exchange.
 * The time is a minimum delay in milliseconds until the timer fires.
 * Used by upper level protocols to time out the exchange.
 * The timer is cancelled when it fires or when the exchange completes.
 * Returns non-zero if a timer couldn't be allocated.
 */
void fc_exch_timer_set(struct fc_exch *ep, u_int timer_msec)
{
	sa_timer_set(&ep->ex_timer, timer_msec * 1000);
}

/*
 * Abort the exchange for a sequence due to timeout or an upper-level abort.
 * Called without the exchange manager em_lock held.
 * Returns non-zero if a sequence could not be allocated.
 */
int fc_seq_abort_exch(const struct fc_seq *req_sp)
{
	struct fc_seq *sp;
	struct fc_exch *ep;
	struct fc_frame *fp;
	int error;

	ep = fc_seq_exch(req_sp);

	/*
	 * Send the abort on a new sequence if possible.
	 */
	error = ENOMEM;
	sp = fc_seq_start(ep);
	if (sp) {

		/*
		 * If not logged into the fabric, don't send ABTS but leave
		 * sequence active until next timeout.
		 */
		if (!ep->ex_s_id) {
			sp->seq_active = 1;	/* pretend we used sequence */
			fc_seq_release(sp);
			return 0;
		}

		/*
		 * Send an abort for the sequence that timed out.
		 */
		fp = fc_frame_alloc(ep->ex_port, 0);
		if (fp) {
			fc_frame_setup(fp, FC_RCTL_BA_ABTS, FC_TYPE_BLS);
			sp->seq_f_ctl |= FC_FC_SEQ_INIT;
			ep->ex_e_stat |= ESB_ST_SEQ_INIT;
			error = fc_seq_send(sp, fp);
		} else {
			fc_seq_release(sp);
		}
	}
	return error;
}

/*
 * Mark a sequence and its exchange both complete.
 * Caller holds the sequence but not the exchange.
 * This call releases the sequence for the caller.
 * This is usually used when a sequence has been allocated but couldn't be
 * sent for some reason, e.g., when a fc_frame_alloc() fails.
 */
void fc_seq_exch_complete(struct fc_seq *sp)
{
	fc_exch_complete(fc_seq_exch(sp));
	fc_seq_complete(sp);
	fc_seq_release(sp);
}

/*
 * Mark exchange complete - internal version called with ex_lock held.
 */
static void fc_exch_complete_locked(struct fc_exch *ep)
{
	fc_seq_hold(&ep->ex_seq);
	fc_seq_complete(&ep->ex_seq);
	fc_seq_release(&ep->ex_seq);
	ep->ex_e_stat |= ESB_ST_COMPLETE;
	ep->ex_recv = NULL;
	ep->ex_errh = NULL;
	if (sa_timer_active(&ep->ex_timer))
		sa_timer_cancel(&ep->ex_timer);
}

/*
 * Mark exchange complete.
 * The state may be available for ILS Read Exchange Status (RES) for a time.
 * The caller doesn't necessarily hold the exchange.
 */
void fc_exch_complete(struct fc_exch *ep)
{
	fc_exch_complete_locked(ep);
}

/*
 * Allocate a new exchange.
 */
static struct fc_exch *fc_exch_alloc(struct fc_exch_mgr *mp)
{
	struct fc_exch_pool *pp;
	struct fc_exch *ep = NULL;

	pp = &mp->em_pool[0];

	if (list_empty(&pp->emp_exch_free)) {
		mp->em_stats.ems_error_no_free_exch++;
	} else {
		ep = list_first_entry(&pp->emp_exch_free, struct fc_exch, ex_list);
		list_del(&ep->ex_list);
		list_add_tail(&ep->ex_list, &pp->emp_exch_busy);
		pp->emp_exch_in_use++;

		/*
		 * Clear the portion of the exchange not maintained
		 * for the duration of the exchange manager.
		 */
		memset((char *)ep +
		       offsetof(struct fc_exch, fc_exch_clear_start), 0,
		       sizeof(*ep) - offsetof(struct fc_exch,
					      fc_exch_clear_start));
		ep->ex_f_ctl = FC_FC_FIRST_SEQ;	/* next seq is first seq */
		ep->ex_rx_id = FC_XID_UNKNOWN;
		ep->ex_class = mp->em_class;

		/*
		 * Set up as if originator.  Caller may change this.
		 */
		ep->ex_ox_id = ep->ex_xid;
		fc_exch_hold(ep);	/* hold for caller */
	}
	return ep;
}

/*
 * Allocate a new exchange as originator.
 */
static struct fc_exch *fc_exch_orig(struct fc_exch_mgr *mp)
{
	struct fc_exch *ep;

	ep = fc_exch_alloc(mp);
	if (ep)
		ep->ex_e_stat |= ESB_ST_SEQ_INIT;
	return ep;
}

/*
 * Allocate a new exchange as responder.
 * Sets the responder ID in the frame header.
 */
static struct fc_exch *fc_exch_resp(struct fc_exch_mgr *mp,
				    const struct fc_frame *fp)
{
	struct fc_exch *ep;
	struct fc_frame_header *fh;
	u_int16_t rx_id;

	ep = fc_exch_alloc(mp);
	if (ep) {
		ep->ex_port = fp->fr_in_port;
		ep->ex_class = fc_frame_class(fp);

		/*
		 * Set EX_CTX indicating we're responding on this exchange.
		 */
		ep->ex_f_ctl |= FC_FC_EX_CTX;	/* we're responding */
		ep->ex_f_ctl &= ~FC_FC_FIRST_SEQ;	/* not new */
		fh = fc_frame_header_get(fp);
		ep->ex_s_id = net24_get(&fh->fh_d_id);
		ep->ex_d_id = net24_get(&fh->fh_s_id);
		ep->ex_orig_fid = ep->ex_d_id;

		/*
		 * fc_exch_alloc() has placed the XID in the originator field.
		 * Move it to the responder field, and set the originator
		 * XID from the frame.
		 */
		ep->ex_rx_id = ep->ex_xid;
		ep->ex_ox_id = net16_get(&fh->fh_ox_id);
		ep->ex_e_stat |= ESB_ST_RESP | ESB_ST_SEQ_INIT;
		if ((net24_get(&fh->fh_f_ctl) & FC_FC_SEQ_INIT) == 0)
			ep->ex_e_stat &= ~ESB_ST_SEQ_INIT;

		/*
		 * Set the responder ID in the frame header.
		 * The old one should've been 0xffff.
		 * If it isn't, don't assign one.
		 * Incoming basic link service frames may specify
		 * a referenced RX_ID.
		 */
		if (fh->fh_type != FC_TYPE_BLS) {
			rx_id = net16_get(&fh->fh_rx_id);
			net16_put(&fh->fh_rx_id, ep->ex_rx_id);
		}
	}
	return ep;
}

/*
 * Find a sequence for receive where the other end is originating the sequence.
 */
static enum fc_pf_rjt_reason
fc_seq_lookup_recip(struct fc_exch_mgr *mp, struct fc_frame *fp)
{
	struct fc_frame_header *fh = fc_frame_header_get(fp);
	struct fc_exch *ep = NULL;
	struct fc_seq *sp = NULL;
	enum fc_pf_rjt_reason reject = FC_RJT_NONE;
	u_int32_t f_ctl;
	fc_xid_t xid;

	f_ctl = net24_get(&fh->fh_f_ctl);

	/*
	 * Lookup or create the exchange if we will be creating the sequence.
	 */
	if (f_ctl & FC_FC_EX_CTX) {
		xid = net16_get(&fh->fh_ox_id);	/* we originated exch */
		ep = fc_exch_lookup(mp, xid);
		if (!ep) {
			mp->em_stats.ems_error_xid_not_found++;
			reject = FC_RJT_OX_ID;
			goto out;
		}
		fc_exch_hold(ep);
		if (ep->ex_rx_id == FC_XID_UNKNOWN)
			ep->ex_rx_id = net16_get(&fh->fh_rx_id);
	} else {
		xid = net16_get(&fh->fh_rx_id);	/* we are the responder */

		/*
		 * Special case for MDS issuing an ELS TEST with a
		 * bad rx_id of 0.
		 * XXX take this out once we do the proper reject.
		 */
		if (xid == 0 && fh->fh_r_ctl == FC_RCTL_ELS_REQ &&
		    fc_frame_payload_op(fp) == ELS_TEST) {
			net16_put(&fh->fh_rx_id, FC_XID_UNKNOWN);
			xid = FC_XID_UNKNOWN;
		}

		/*
		 * new sequence - find the exchange
		 */
		ep = fc_exch_lookup(mp, xid);
		if ((f_ctl & FC_FC_FIRST_SEQ) && fc_sof_is_init(fp->fr_sof)) {
			if (ep) {
				mp->em_stats.ems_error_xid_busy++;
				reject = FC_RJT_RX_ID;
				goto out;
			}
			ep = fc_exch_resp(mp, fp);
			if (!ep) {
				reject = FC_RJT_EXCH_EST;	/* XXX */
				goto out;
			}
			xid = ep->ex_xid;	/* get our XID */
		} else if (ep) {
			fc_exch_hold(ep);	/* hold matches alloc */
		} else {
			mp->em_stats.ems_error_xid_not_found++;
			reject = FC_RJT_RX_ID;	/* XID not found */
			goto out;
		}
	}

	/*
	 * At this point, we should have the exchange.
	 * Find or create the sequence.
	 */
	if (fc_sof_is_init(fp->fr_sof)) {
		sp = fc_seq_alloc(ep, fh->fh_seq_id);
		fc_exch_release(ep);	/* sequence now holds exch */
		if (!sp) {
			reject = FC_RJT_SEQ_XS;	/* exchange shortage */
			goto out;
		}
		sp->seq_s_stat |= SSB_ST_RESP;
	} else {
		sp = &ep->ex_seq;
		if (sp->seq_id == fh->fh_seq_id) {
			fc_seq_hold(sp);	/* hold to match alloc */
			fc_exch_release(ep);	/* sequence now holds exch */
		} else {
			mp->em_stats.ems_error_seq_not_found++;
			reject = FC_RJT_SEQ_ID;	/* sequence should exist */
			fc_exch_release(ep);
			goto out;
		}
	}

	if (f_ctl & FC_FC_SEQ_INIT)
		ep->ex_e_stat |= ESB_ST_SEQ_INIT;
	sp->seq_active = 1;
	fp->fr_seq = sp;
out:
	return reject;
}

/*
 * Find the sequence for a frame being received.
 * We originated the sequence, so it should be found.
 * We may or may not have originated the exchange.
 * Does not hold the sequence for the caller.
 */
static struct fc_seq *fc_seq_lookup_orig(struct fc_exch_mgr *mp,
					 struct fc_frame *fp)
{
	struct fc_frame_header *fh = fc_frame_header_get(fp);
	struct fc_exch *ep;
	struct fc_seq *sp = NULL;
	u_int32_t f_ctl;
	fc_xid_t xid;

	f_ctl = net24_get(&fh->fh_f_ctl);
	xid = net16_get((f_ctl & FC_FC_EX_CTX) ? &fh->fh_ox_id : &fh->fh_rx_id);
	ep = fc_exch_lookup(mp, xid);
	if (ep && ep->ex_seq.seq_id == fh->fh_seq_id) {

		/*
		 * Save the RX_ID if we didn't previously know it.
		 */
		sp = &ep->ex_seq;
		if ((f_ctl & FC_FC_EX_CTX) != 0 &&
		    ep->ex_rx_id == FC_XID_UNKNOWN) {
			ep->ex_rx_id = net16_get(&fh->fh_rx_id);
		}
	}
	return (sp);
}

/*
 * Set the output port to be used for an exchange.
 */
void fc_exch_set_port(struct fc_exch *ep, struct fc_port *port)
{
	ep->ex_port = port;
}

/*
 * Set addresses for an exchange.
 */
void fc_exch_set_addr(struct fc_exch *ep, fc_fid_t orig_id, fc_fid_t resp_id)
{
	ep->ex_orig_fid = orig_id;
	if (ep->ex_e_stat & ESB_ST_RESP) {
		ep->ex_s_id = resp_id;
		ep->ex_d_id = orig_id;
	} else {
		ep->ex_s_id = orig_id;
		ep->ex_d_id = resp_id;
	}
}

/*
 * Set addresses for the exchange of a sequence.
 */
void fc_seq_set_addr(struct fc_seq *sp, fc_fid_t orig_fid, fc_fid_t resp_fid)
{
	fc_exch_set_addr(fc_seq_exch(sp), orig_fid, resp_fid);
}

/*
 * Start a new sequence as originator on an existing exchange.
 * This will never return NULL.
 */
struct fc_seq *fc_seq_start(struct fc_exch *ep)
{
	struct fc_seq *sp = NULL;

	sp = fc_seq_alloc(ep, ep->ex_seq_id++);
	if (fc_exch_debug)
		dprintf("exch %4x f_ctl %6x seq %2x f_ctl %6x\n",
		       ep->ex_xid, ep->ex_f_ctl, sp->seq_id, sp->seq_f_ctl);
	return sp;
}

/*
 * Allocate a new sequence on the same exchange as the supplied sequence.
 * This will never return NULL.
 */
struct fc_seq *fc_seq_start_next(struct fc_seq *sp)
{
	return fc_seq_start(fc_seq_exch(sp));
}

/*
 * Allocate a new sequence on the same exchange as the supplied sequence.
 * also set the f_ctl of the new sequence
 * This will never return NULL.
 */
struct fc_seq *fc_seq_start_next_fctl(struct fc_seq *sp, u_int32_t f_ctl)
{
	struct fc_seq *new_sp;

	new_sp = fc_seq_start(fc_seq_exch(sp));
	if (new_sp)
		new_sp->seq_f_ctl = f_ctl;
	return new_sp;
}

/*
 * Set the receive handler and arg for the exchange of an existing sequence.
 */
void fc_seq_set_recv(struct fc_seq *sp,
		     void (*recv) (struct fc_seq *,
				   struct fc_frame *, void *), void *arg)
{
	struct fc_exch *ep = fc_seq_exch(sp);

	ep->ex_recv = recv;
	ep->ex_recv_arg = arg;
}

/*
 * Start a new sequence as originator on a new exchange.
 * Returns with a reference count held on the sequence but not on the exchange
 * for the caller.  The exchange will be held for the sequence.
 */
struct fc_seq *fc_seq_start_exch(struct fc_exch_mgr *mp,
				 void (*recv) (struct fc_seq *,
					       struct fc_frame *, void *),
				 void (*errh) (enum fc_event, void *),
				 void *arg, fc_fid_t sid, fc_fid_t did)
{
	struct fc_exch *ep;
	struct fc_seq *sp;

	ep = fc_exch_orig(mp);
	sp = NULL;
	if (ep) {
		fc_exch_set_addr(ep, sid, did);
		ep->ex_recv = recv;
		ep->ex_errh = errh;
		ep->ex_recv_arg = arg;
		sp = fc_seq_start(ep);
		fc_exch_release(ep);
	}
	return sp;
}

size_t fc_seq_mfs(struct fc_seq *sp)
{
	size_t mfs;

	mfs = fc_seq_exch(sp)->ex_max_payload;
	return mfs;
}

/*
 * Send a frame in a sequence where more will follow.
 *
 * This sets some of the F_CTL flags in the packet, depending on the
 * state of the sequence and exchange.
 *
 * FC_FC_EX_CTX is set if we're responding to the exchange.
 * FC_FC_SEQ_CTX is set if we're responding to the sequence.
 * FC_FC_FIRST_SEQ is set on every frame in the first sequence of the exchange.
 * FC_FC_LAST_SEQ is set on every frame in the last sequence of the exchange.
 * FC_FC_END_SEQ is set on the last frame of a sequence (not here).
 *
 * Some f_ctl bits must be specified in the fc_seq by the caller:
 * FC_FC_SEQ_INIT is set by the caller if sequence initiative should
 * be transferred.  FC_FC_LAST_SEQ is set on the last sequence of the exchange.
 *
 * This will update the following flags for the sequence and exchange:
 * In the exchange, FC_FC_FIRST_SEQ is set on creation of originating
 * exchanges, it is used to initialize the flags in the first sequence
 * and then cleared in the exchange.
 */
int fc_seq_send_frag(struct fc_seq *sp, struct fc_frame *fp)
{
	struct fc_exch *ep;
	struct fc_port *port;
	struct fc_frame_header *fh;
	enum fc_class class;
	u_int32_t f_ctl;
	int error;

	ep = fc_seq_exch(sp);
	port = ep->ex_port;

	class = ep->ex_class;
	fp->fr_sof = class;
	if (sp->seq_cnt)
		fp->fr_sof = fc_sof_normal(class);

	/*
	 * Save sequence initiative flag for the final frame, and take it out
	 * of the flags until then.
	 */
	f_ctl = sp->seq_f_ctl | ep->ex_f_ctl;
	f_ctl &= ~FC_FC_SEQ_INIT;
	fp->fr_eof = FC_EOF_N;

	fc_seq_fill_hdr(sp, fp);

	fh = fc_frame_header_get(fp);
	net24_put(&fh->fh_f_ctl, f_ctl);
	net16_put(&fh->fh_seq_cnt, sp->seq_cnt++);

	/*
	 * Send the frame.
	 */
	error = fc_port_egress(port, fp);

	/*
	 * Update the exchange and sequence flags.
	 */
	sp->seq_f_ctl = f_ctl;	/* save for possible abort */
	ep->ex_f_ctl &= ~FC_FC_FIRST_SEQ;	/* not first seq */
	sp->seq_active = 1;
	return error;
}

/*
 * Send the last frame of a sequence.
 * See notes on fc_seq_send_next(), above.
 */
int fc_seq_send(struct fc_seq *sp, struct fc_frame *fp)
{
	struct fc_exch *ep;
	struct fc_port *port;
	struct fc_frame_header *fh;
	enum fc_class class;
	u_int32_t f_ctl;
	u_int16_t fill;
	int error;

	ep = fc_seq_exch(sp);
	port = ep->ex_port;

	class = ep->ex_class;
	fp->fr_sof = class;
	if (sp->seq_cnt)
		fp->fr_sof = fc_sof_normal(class);
	fp->fr_eof = FC_EOF_T;
	if (fc_sof_needs_ack(class))
		fp->fr_eof = FC_EOF_N;

	fc_seq_fill_hdr(sp, fp);
	fh = fc_frame_header_get(fp);

	/*
	 * Form f_ctl.
	 * The number of fill bytes to make the length a 4-byte multiple is
	 * the low order 2-bits of the f_ctl.  The fill itself will have been
	 * cleared by the frame allocation.
	 * After this, the length will be even, as expected by the transport.
	 * Don't include the fill in the f_ctl saved in the sequence.
	 */
	fill = fp->fr_len & 3;
	if (fill) {
		fill = 4 - fill;
		fp->fr_len += fill;
	}
	f_ctl = sp->seq_f_ctl | ep->ex_f_ctl | FC_FC_END_SEQ;
	net24_put(&fh->fh_f_ctl, f_ctl | fill);
	net16_put(&fh->fh_seq_cnt, sp->seq_cnt++);

	/*
	 * Send the frame.
	 */
	error = fc_port_egress(port, fp);

	/*
	 * Update the exchange and sequence flags,
	 * assuming all frames for the sequence have been sent.
	 * We can only be called to send once for each sequence.
	 */
	sp->seq_f_ctl = f_ctl;	/* save for possible abort */
	ep->ex_f_ctl &= ~FC_FC_FIRST_SEQ;	/* not first seq */
	sp->seq_active = 1;
	if (f_ctl & FC_FC_LAST_SEQ)
		fc_exch_complete_locked(ep);
	if (f_ctl & FC_FC_SEQ_INIT)
		ep->ex_e_stat &= ~ESB_ST_SEQ_INIT;
	fc_seq_release(sp);
	return error;
}

/*
 * Send a sequence, which is also the last sequence in the exchange.
 * See notes on fc_seq_send();
 */
int fc_seq_send_last(struct fc_seq *sp, struct fc_frame *fp,
		     enum fc_rctl rctl, enum fc_fh_type fh_type)
{
	sp->seq_f_ctl |= FC_FC_LAST_SEQ;
	fc_frame_setup(fp, rctl, fh_type);
	return fc_seq_send(sp, fp);
}

/*
 * Send a request sequence, and transfer sequence initiative.
 * See notes on fc_seq_send();
 */
int fc_seq_send_tsi(struct fc_seq *sp, struct fc_frame *fp)
{
	sp->seq_f_ctl |= FC_FC_SEQ_INIT;
	return fc_seq_send(sp, fp);
}

/*
 * Send a request sequence, and transfer sequence initiative.
 * See notes on fc_seq_send();
 */
int fc_seq_send_req(struct fc_seq *sp, struct fc_frame *fp,
		    enum fc_rctl rctl, enum fc_fh_type fh_type,
		    u_int32_t parm_offset)
{
	sp->seq_f_ctl |= FC_FC_SEQ_INIT;
	fc_frame_setup(fp, rctl, fh_type);
	fc_frame_set_offset(fp, parm_offset);
	return fc_seq_send(sp, fp);
}

/*
 * Send a request sequence, using a new sequence on the same exchange
 * as the supplied one, and transfer sequence initiative.
 * See notes on fc_seq_send();
 */
int fc_seq_send_next_req(struct fc_seq *sp, struct fc_frame *fp)
{
	sp = fc_seq_start_next(sp);
	sp->seq_f_ctl |= FC_FC_SEQ_INIT;
	return fc_seq_send(sp, fp);
}

/*
 * Send ACK_1 (or equiv.) indicating we received something.
 * The frame we're acking is supplied.
 */
static void fc_seq_send_ack(struct fc_seq *sp, const struct fc_frame *rx_fp)
{
	struct fc_frame *fp;
	struct fc_frame_header *rx_fh;
	struct fc_frame_header *fh;
	u_int f_ctl;

	/*
	 * Don't send ACKs for class 3.
	 */
	if (fc_sof_needs_ack(rx_fp->fr_sof)) {
		fp = fc_frame_alloc(fc_seq_exch(sp)->ex_port, 0);
		if (!fp)
			return;
		fc_seq_fill_hdr(sp, fp);
		fh = fc_frame_header_get(fp);
		fh->fh_r_ctl = FC_RCTL_ACK_1;
		fh->fh_type = FC_TYPE_BLS;

		/*
		 * Form f_ctl by inverting EX_CTX and SEQ_CTX (bits 23, 22).
		 * Echo FIRST_SEQ, LAST_SEQ, END_SEQ, END_CONN, SEQ_INIT.
		 * Bits 9-8 are meaningful (retransmitted or unidirectional).
		 * Last ACK uses bits 7-6 (continue sequence),
		 * bits 5-4 are meaningful (what kind of ACK to use).
		 */
		rx_fh = fc_frame_header_get(rx_fp);
		f_ctl = net24_get(&rx_fh->fh_f_ctl);
		f_ctl &= FC_FC_EX_CTX | FC_FC_SEQ_CTX |
		    FC_FC_FIRST_SEQ | FC_FC_LAST_SEQ |
		    FC_FC_END_SEQ | FC_FC_END_CONN | FC_FC_SEQ_INIT |
		    FC_FC_RETX_SEQ | FC_FC_UNI_TX;
		f_ctl ^= FC_FC_EX_CTX | FC_FC_SEQ_CTX;
		net24_put(&fh->fh_f_ctl, f_ctl);

		fh->fh_seq_id = rx_fh->fh_seq_id;
		fh->fh_seq_cnt = rx_fh->fh_seq_cnt;
		net32_put(&fh->fh_parm_offset, 1);	/* ack single frame */

		fp->fr_sof = rx_fp->fr_sof;
		if (f_ctl & FC_FC_END_SEQ) {
			fp->fr_eof = FC_EOF_T;
		} else {
			fp->fr_eof = FC_EOF_N;
		}
		(void)fc_port_egress(rx_fp->fr_in_port, fp);
	}
}

/*
 * Handle receive where the other end is originating the sequence.
 */
void fc_exch_recv_req(struct fc_exch_mgr *mp, struct fc_frame *fp,
		      size_t max_payload,
		      void (*dflt_recv) (struct fc_seq *, struct fc_frame *,
					 void *), void *arg)
{
	struct fc_frame_header *fh = fc_frame_header_get(fp);
	enum fc_event event = FC_EV_NONE;
	struct fc_seq *sp = NULL;
	struct fc_exch *ep = NULL;
	enum fc_sof sof;
	enum fc_eof eof;
	u_int32_t f_ctl;
	enum fc_pf_rjt_reason reject;
	void (*errh) (enum fc_event, void *);
	void (*recv) (struct fc_seq *, struct fc_frame *, void *);
	void *ex_arg;

	fp->fr_seq = NULL;
	reject = fc_seq_lookup_recip(mp, fp);
	if (reject == FC_RJT_NONE) {
		sp = fp->fr_seq;	/* sequence will be held */
		ep = fc_seq_exch(sp);
		ep->ex_max_payload = (u_int16_t) max_payload;
		sof = fp->fr_sof;
		eof = fp->fr_eof;
		f_ctl = net24_get(&fh->fh_f_ctl);
		fc_seq_send_ack(sp, fp);

		recv = ep->ex_recv;
		ex_arg = ep->ex_recv_arg;
		errh = ep->ex_errh;
		if (eof == FC_EOF_T &&
		    (f_ctl & (FC_FC_LAST_SEQ | FC_FC_END_SEQ)) ==
		    (FC_FC_LAST_SEQ | FC_FC_END_SEQ)) {

			/*
			 * For the last frame of the last sequence,
			 * mark the exchange and all its sequences complete.
			 */
			if ((f_ctl & (FC_FC_LAST_SEQ | FC_FC_END_SEQ)) ==
			    (FC_FC_LAST_SEQ | FC_FC_END_SEQ))
				fc_exch_complete_locked(ep);
			fc_seq_complete(sp);
		}

		if (fh->fh_type == FC_TYPE_BLS) {
			/*
			 * Basic link service -
			 * XXX need to handle abort here.
			 */
			switch (fh->fh_r_ctl) {
			case FC_RCTL_BA_ACC:
				event = FC_EV_ACC;
				break;
			case FC_RCTL_BA_NOP:
				break;
			case FC_RCTL_BA_RJT:
			case FC_RCTL_BA_ABTS:
			default:
				event = FC_EV_RJT;
				break;
			}
			if (event != FC_EV_NONE) {
				if (fc_exch_debug)
					dprintf("exch: BLS rctl %x - %s\n",
					       fh->fh_r_ctl,
					       fc_exch_rctl_name(fh->fh_r_ctl));
				if (errh)
					(*errh) (event, ex_arg);
			}
			fc_frame_free(fp);
		} else {
			/*
			 * Call the receive function.
			 * The sequence is held (has a refcnt) for us,
			 * but not for the receive function.  The receive
			 * function is not expected to do a fc_seq_release()
			 * or fc_seq_complete().
			 *
			 * The receive function may allocate a new sequence
			 * over the old one, so we shouldn't change the
			 * sequence after this.
			 *
			 * The frame will be freed by the receive function.
			 */
			if (recv)
				(recv) (sp, fp, ex_arg);
			else
				(*dflt_recv) (sp, fp, arg);
		}
		fp = NULL;	/* frame has been freed */
		fc_seq_release(sp);
	} else {
		if (fc_exch_debug)
			dprintf("exch/seq lookup failed: reject %x\n", reject);
		fc_frame_free(fp);
	}
}

/*
 * Handle receive where the other end is originating the sequence in
 * response to our exchange.
 */
void fc_exch_recv_seq_resp(struct fc_exch_mgr *mp, struct fc_frame *fp)
{
	struct fc_frame_header *fh = fc_frame_header_get(fp);
	struct fc_seq *sp;
	struct fc_exch *ep;
	enum fc_sof sof;
	u_int32_t f_ctl;
	void (*recv)(struct fc_seq *, struct fc_frame *, void *);
	void *ex_arg;

	ep = fc_exch_lookup(mp, net16_get(&fh->fh_ox_id));
	if (!ep) {
		mp->em_stats.ems_error_xid_not_found++;
		goto out;
	}
	if (ep->ex_rx_id == FC_XID_UNKNOWN)
		ep->ex_rx_id = net16_get(&fh->fh_rx_id);
	if (ep->ex_s_id != 0 && ep->ex_s_id != net24_get(&fh->fh_d_id)) {
		mp->em_stats.ems_error_xid_not_found++;
		goto out;
	}
	if (ep->ex_d_id != net24_get(&fh->fh_s_id) &&
	    ep->ex_d_id != FC_FID_FLOGI) {
		mp->em_stats.ems_error_xid_not_found++;
		goto out;
	}
	sof = fp->fr_sof;
	if (fc_sof_is_init(sof)) {
		sp = fc_seq_alloc(ep, fh->fh_seq_id);
		sp->seq_s_stat |= SSB_ST_RESP;
	} else {
		sp = &ep->ex_seq;
		if (sp->seq_id != fh->fh_seq_id) {
			mp->em_stats.ems_error_seq_not_found++;
			goto out;
		}
		fc_seq_hold(sp);	/* hold to match alloc */
	}
	f_ctl = net24_get(&fh->fh_f_ctl);
	if (f_ctl & FC_FC_SEQ_INIT)
		ep->ex_e_stat |= ESB_ST_SEQ_INIT;
	sp->seq_active = 1;
	fp->fr_seq = sp;
	if (fc_sof_needs_ack(sof))
		fc_seq_send_ack(sp, fp);
	recv = ep->ex_recv;
	ex_arg = ep->ex_recv_arg;

	if (fp->fr_eof == FC_EOF_T &&
	    (f_ctl & (FC_FC_LAST_SEQ | FC_FC_END_SEQ)) ==
	    (FC_FC_LAST_SEQ | FC_FC_END_SEQ)) {

		/*
		 * For the last frame of the last sequence,
		 * mark the exchange and all its sequences complete.
		 */
		if ((f_ctl & (FC_FC_LAST_SEQ | FC_FC_END_SEQ)) ==
		    (FC_FC_LAST_SEQ | FC_FC_END_SEQ))
			fc_exch_complete_locked(ep);

		fc_seq_complete(sp);
	}

	/*
	 * Call the receive function.
	 * The sequence is held (has a refcnt) for us,
	 * but not for the receive function.  The receive
	 * function is not expected to do a fc_seq_release()
	 * or fc_seq_complete().
	 *
	 * The receive function may allocate a new sequence
	 * over the old one, so we shouldn't change the
	 * sequence after this.
	 *
	 * The frame will be freed by the receive function.
	 */
	if (recv)
		(*recv) (sp, fp, ex_arg);
	else
		fc_frame_free(fp);
	fp = NULL;	/* frame has been freed */
	fc_seq_release(sp);
	return;
out:
	fc_frame_free(fp);
}

/*
 * Handle receive for a sequence where other end is responding to our sequence.
 */
void fc_exch_recv_resp(struct fc_exch_mgr *mp, struct fc_frame *fp)
{
	struct fc_frame_header *fh = fc_frame_header_get(fp);
	struct fc_seq *sp;
	struct fc_exch *ep;
	u_int32_t f_ctl;
	enum fc_pf_rjt_reason reject = FC_RJT_NONE;

	sp = fc_seq_lookup_orig(mp, fp);	/* doesn't hold sequence */
	if (!sp) {
		mp->em_stats.ems_error_xid_not_found++;
		reject = FC_RJT_SEQ_ID;
		if (fc_exch_debug)
			dprintf("seq lookup failed: reject %x\n", reject);
	} else {
		ep = fc_seq_exch(sp);
		if (fh->fh_type == FC_TYPE_BLS) {
			f_ctl = net24_get(&fh->fh_f_ctl);
			if (f_ctl & FC_FC_SEQ_INIT)
				ep->ex_e_stat |= ESB_ST_SEQ_INIT;

			/*
			 * Basic link service -
			 * XXX need to handle ack/rjct/abort here.
			 */
			switch (fh->fh_r_ctl) {
			case FC_RCTL_ACK_1:
				fc_seq_hold(sp);
				fc_seq_complete(sp);
				fc_seq_release(sp);
				break;
			default:
				if (fc_exch_debug)
					dprintf("BLS rctl %x - %s\n",
					       fh->fh_r_ctl,
					       fc_exch_rctl_name(fh->fh_r_ctl));
				break;
			}
		} else {
			mp->em_stats.ems_error_non_bls_resp++;
			if (fc_exch_debug) {
				dprintf("non-BLS response to sequence");
/* 				fc_print_frame_hdr("fc_seq_recv_resp: " */
/* 						   "non BLS response", fp); */
			}
		}
	}
	fc_frame_free(fp);
}

/*
 * Fill in frame header.
 *
 * The following fields are the responsibility of this routine:
 *      d_id, s_id, df_ctl, ox_id, rx_id, cs_ctl, seq_id
 *
 * The following fields are handled by the caller.
 *      r_ctl, type, f_ctl, seq_cnt, parm_offset
 *
 * That should be a complete list.
 *
 * We may be the originator or responder to the exchange.
 * We may be the originator or responder to the sequence.
 */
static void fc_seq_fill_hdr(struct fc_seq *sp, struct fc_frame *fp)
{
	struct fc_frame_header *fh = fc_frame_header_get(fp);
	struct fc_exch *ep;

	ep = fc_seq_exch(sp);

	net24_put(&fh->fh_s_id, ep->ex_s_id);
	net24_put(&fh->fh_d_id, ep->ex_d_id);
	net16_put(&fh->fh_ox_id, ep->ex_ox_id);
	net16_put(&fh->fh_rx_id, ep->ex_rx_id);
	fh->fh_seq_id = sp->seq_id;
	fh->fh_cs_ctl = 0;
	fh->fh_df_ctl = 0;
}

/*
 * Accept sequence with LS_ACC.
 * If this fails due to allocation or transmit congestion, assume the
 * originator will repeat the sequence.
 */
void fc_seq_ls_acc(struct fc_seq *req_sp)
{
	struct fc_seq *sp;
	struct fc_els_ls_acc *acc;
	struct fc_frame *fp;

	sp = fc_seq_start_next(req_sp);
	fp = fc_frame_alloc(fc_seq_exch(sp)->ex_port, sizeof(*acc));
	if (fp) {
		acc = fc_frame_payload_get(fp, sizeof(*acc));
		memset(acc, 0, sizeof(*acc));
		acc->la_cmd = ELS_LS_ACC;
		fc_seq_send_last(sp, fp, FC_RCTL_ELS_REP, FC_TYPE_ELS);
	} else {
		fc_seq_exch_complete(sp);
	}
}

/*
 * Reject sequence with ELS LS_RJT.
 * If this fails due to allocation or transmit congestion, assume the
 * originator will repeat the sequence.
 */
void fc_seq_ls_rjt(struct fc_seq *req_sp, enum fc_els_rjt_reason reason,
		   enum fc_els_rjt_explan explan)
{
	struct fc_seq *sp;
	struct fc_els_ls_rjt *rjt;
	struct fc_frame *fp;

	sp = fc_seq_start_next(req_sp);
	fp = fc_frame_alloc(fc_seq_exch(sp)->ex_port, sizeof(*rjt));
	if (fp) {
		rjt = fc_frame_payload_get(fp, sizeof(*rjt));
		memset(rjt, 0, sizeof(*rjt));
		rjt->er_cmd = ELS_LS_RJT;
		rjt->er_reason = reason;
		rjt->er_explan = explan;
		fc_seq_send_last(sp, fp, FC_RCTL_ELS_REP, FC_TYPE_ELS);
	} else {
		fc_seq_exch_complete(sp);
	}
}

/*
 * Reset an exchange manager, releasing all sequences and exchanges.
 * If s_id is non-zero, reset only exchanges we source from that FID.
 * If d_id is non-zero, reset only exchanges destined to that FID.
 *
 * Currently, callers always use a d_id of 0, so this could be simplified later.
 */
void fc_exch_mgr_reset(struct fc_exch_mgr *mp, fc_fid_t s_id, fc_fid_t d_id)
{
	struct fc_seq *sp;
	struct fc_exch *ep;
	struct fc_exch *next;
	struct fc_exch_pool *pp;
	unsigned int pool_count = 0;

	for (pp = mp->em_pool; pp < &mp->em_pool[pool_count]; pp++) {
		list_for_each_entry_safe(ep, next, &pp->emp_exch_busy, ex_list) {
			if ((s_id == 0 || s_id == ep->ex_s_id) &&
			    (d_id == 0 || d_id == ep->ex_d_id)) {
				sp = &ep->ex_seq;
				fc_seq_hold(sp);
				if (ep->ex_errh)
					(*ep->ex_errh) (FC_EV_CLOSED,
							ep->ex_recv_arg);
				fc_seq_exch_complete(sp);
			}
		}
	}
}

/*
 * Read exchange concise.
 */
struct fc_seq *fc_seq_rec_req(struct fc_seq *inq_sp,
			      void (*recv) (struct fc_seq *, struct fc_frame *,
					    void *),
			      void (*errh) (enum fc_event, void *), void *arg)
{
	struct fc_seq *sp;
	struct fc_exch *ep;
	struct fc_frame *fp;
	struct fc_els_rec *rp;

	ep = fc_seq_exch(inq_sp);
	fp = fc_frame_alloc(ep->ex_port, sizeof(*rp));
	if (!fp)
		return NULL;
	sp = fc_seq_start_exch(ep->ex_pool->emp_mgr, recv, errh, arg,
			       ep->ex_s_id, ep->ex_d_id);
	if (!sp) {
		fc_frame_free(fp);
		return NULL;
	}
	fc_seq_exch(sp)->ex_port = ep->ex_port;
	rp = fc_frame_payload_get(fp, sizeof(*rp));
	memset(rp, 0, sizeof(*rp));
	rp->rec_cmd = ELS_REC;
	if (ep->ex_f_ctl & FC_FC_EX_CTX)
		net24_put(&rp->rec_s_id, ep->ex_d_id);
	else
		net24_put(&rp->rec_s_id, ep->ex_s_id);
	net16_put(&rp->rec_ox_id, ep->ex_ox_id);
	net16_put(&rp->rec_rx_id, ep->ex_rx_id);
	if (fc_seq_send_req(sp, fp, FC_RCTL_ELS_REQ, FC_TYPE_ELS, 0)) {
		fc_seq_exch_complete(sp);
		sp = NULL;
	}
	return sp;
}
