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
 * Session support.
 *
 * A session is a PLOGI/PRLI session, the state of the conversation between
 * a local port and a remote port.
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

#include "sa_timer.h"
#include "sa_event.h"
#include "sa_hash.h"
#include "sa_state.h"

#include "fc_fs.h"
#include "fc_els.h"
#include "fc_ils.h"
#include "fc_fc2.h"
#include "fc_fcp.h"

#include "fc_types.h"
#include "fc_event.h"
#include "fc_sess.h"
#include "fc_port.h"
#include "fc_frame.h"
#include "fc_local_port.h"
#include "fc_remote_port.h"
#include "fc_exch.h"
#include "fc_event.h"

#include "fc_exch_impl.h"
#include "fc_virt_fab_impl.h"
#include "fc_local_port_impl.h"
#include "fc_sess_impl.h"

/*
 * Debugging tunables which are only set by debugger or at compile time.
 */
static int fc_sess_debug;

/*
 * Declare hash type for lookup of session by local and remote FCID.
 */
#define	FC_SESS_HASH_SIZE       32	/* XXX increase later */

static int fc_sess_match(const sa_hash_key_t, void *);
static u_int32_t fc_sess_hash(const sa_hash_key_t);

static struct sa_hash_type fc_sess_hash_type = {
	.st_link_offset = offsetof(struct fc_sess, fs_hash_link),
	.st_match = fc_sess_match,
	.st_hash = fc_sess_hash,
};

/*
 * static functions.
 */
static void fc_sess_enter_init(struct fc_sess *);
static void fc_sess_enter_started(struct fc_sess *);
static void fc_sess_enter_plogi(struct fc_sess *);
static void fc_sess_enter_prli(struct fc_sess *);
static void fc_sess_enter_rtv(struct fc_sess *);
static void fc_sess_enter_ready(struct fc_sess *);
static void fc_sess_enter_logo(struct fc_sess *);
static void fc_sess_enter_error(struct fc_sess *);
static void fc_sess_local_port_event(int, void *);
static void fc_sess_recv_plogi_req(struct fc_sess *,
				   struct fc_seq *, struct fc_frame *);
static void fc_sess_recv_prli_req(struct fc_sess *,
				  struct fc_seq *, struct fc_frame *);
static void fc_sess_recv_prlo_req(struct fc_sess *,
				  struct fc_seq *, struct fc_frame *);
static void fc_sess_recv_logo_req(struct fc_sess *,
				  struct fc_seq *, struct fc_frame *);
static void fc_sess_delete(struct fc_sess *, void *);
static void fc_sess_timeout(void *);
static void fc_sess_state_event(struct fc_sess *, enum fc_event);

/*
 * Session state transition table.
 */
static const struct sa_state_desc fc_sess_state_desc[] = {
	/*
	 * Declare events.
	 */
	SA_STATE_EVENT(FC_EV_ACC),
	SA_STATE_EVENT(FC_EV_RJT),
	SA_STATE_EVENT(FC_EV_TIMEOUT),
	SA_STATE_EVENT(FC_EV_READY),
	SA_STATE_EVENT(FC_EV_DOWN),
	SA_STATE_EVENT(FC_EV_CLOSED),
	SA_STATE_EVENT(FC_EV_START),
	SA_STATE_EVENT(FC_EV_STOP),

	/*
	 * Associate handlers for entering specific states.
	 */
	SA_STATE_HANDLER(SESS_ST_INIT, fc_sess_enter_init),
	SA_STATE_HANDLER(SESS_ST_STARTED, fc_sess_enter_started),
	SA_STATE_HANDLER(SESS_ST_PLOGI, fc_sess_enter_plogi),
	SA_STATE_HANDLER(SESS_ST_PRLI, fc_sess_enter_prli),
	SA_STATE_HANDLER(SESS_ST_RTV, fc_sess_enter_rtv),
	SA_STATE_HANDLER(SESS_ST_READY, fc_sess_enter_ready),
	SA_STATE_HANDLER(SESS_ST_LOGO, fc_sess_enter_logo),
	SA_STATE_HANDLER(SESS_ST_RESTART, fc_sess_enter_logo),
	SA_STATE_HANDLER(SESS_ST_ERROR, fc_sess_enter_error),

	/*
	 * Declare states and transitions.
	 */
	SA_STATE_NAME(SESS_ST_INIT),
	SA_STATE_NEXT(FC_EV_START, SESS_ST_STARTED),
	SA_STATE_NEXT(FC_EV_DOWN, SESS_ST_INIT),	/* link down */
	SA_STATE_NEXT(FC_EV_CLOSED, SESS_ST_INIT),	/* received LOGO */
	SA_STATE_NEXT(FC_EV_STOP, SESS_ST_INIT),
	SA_STATE_NEXT(FC_EV_RJT, SESS_ST_INIT),

	SA_STATE_NAME(SESS_ST_STARTED),	/* wait for local_port ready */
	SA_STATE_NEXT(FC_EV_ACC, SESS_ST_PLOGI),
	SA_STATE_NEXT(FC_EV_READY, SESS_ST_PLOGI),
	SA_STATE_NEXT(FC_EV_STOP, SESS_ST_INIT),	/* TBD need handler */
	SA_STATE_NEXT(FC_EV_DOWN, SESS_ST_INIT),
	SA_STATE_NEXT(FC_EV_CLOSED, SESS_ST_INIT),

	SA_STATE_NAME(SESS_ST_PLOGI),
	SA_STATE_NEXT(FC_EV_ACC, SESS_ST_PRLI),
	SA_STATE_NEXT(FC_EV_TIMEOUT, SESS_ST_PLOGI),
	SA_STATE_NEXT(FC_EV_RJT, SESS_ST_ERROR),
	SA_STATE_NEXT(FC_EV_DOWN, SESS_ST_INIT),
	SA_STATE_NEXT(FC_EV_CLOSED, SESS_ST_INIT),

	SA_STATE_NAME(SESS_ST_PLOGI_RECV),
	SA_STATE_NEXT(FC_EV_CLOSED, SESS_ST_INIT),
	SA_STATE_NEXT(FC_EV_DOWN, SESS_ST_INIT),
	SA_STATE_NEXT(FC_EV_CLOSED, SESS_ST_INIT),

	SA_STATE_NAME(SESS_ST_PRLI),
	SA_STATE_NEXT(FC_EV_ACC, SESS_ST_RTV),
	SA_STATE_NEXT(FC_EV_STOP, SESS_ST_LOGO),
	SA_STATE_NEXT(FC_EV_TIMEOUT, SESS_ST_PRLI),
	SA_STATE_NEXT(FC_EV_RJT, SESS_ST_ERROR),
	SA_STATE_NEXT(FC_EV_DOWN, SESS_ST_INIT),
	SA_STATE_NEXT(FC_EV_CLOSED, SESS_ST_INIT),

	SA_STATE_NAME(SESS_ST_RTV),
	SA_STATE_NEXT(FC_EV_ACC, SESS_ST_READY),
	SA_STATE_NEXT(FC_EV_STOP, SESS_ST_LOGO),
	SA_STATE_NEXT(FC_EV_TIMEOUT, SESS_ST_RTV),
	SA_STATE_NEXT(FC_EV_RJT, SESS_ST_READY),
	SA_STATE_NEXT(FC_EV_DOWN, SESS_ST_INIT),
	SA_STATE_NEXT(FC_EV_CLOSED, SESS_ST_INIT),

	SA_STATE_NAME(SESS_ST_READY),
	SA_STATE_NEXT(FC_EV_STOP, SESS_ST_LOGO),
	SA_STATE_NEXT(FC_EV_DOWN, SESS_ST_INIT),
	SA_STATE_NEXT(FC_EV_CLOSED, SESS_ST_INIT),

	SA_STATE_NAME(SESS_ST_LOGO),
	SA_STATE_NEXT(FC_EV_ACC, SESS_ST_INIT),
	SA_STATE_NEXT(FC_EV_TIMEOUT, SESS_ST_INIT),
	SA_STATE_NEXT(FC_EV_DOWN, SESS_ST_INIT),
	SA_STATE_NEXT(FC_EV_CLOSED, SESS_ST_INIT),
	SA_STATE_NEXT(FC_EV_STOP, SESS_ST_LOGO),

	SA_STATE_NAME(SESS_ST_RESTART),
	SA_STATE_NEXT(FC_EV_ACC, SESS_ST_INIT),
	SA_STATE_NEXT(FC_EV_TIMEOUT, SESS_ST_INIT),
	SA_STATE_NEXT(FC_EV_DOWN, SESS_ST_INIT),
	SA_STATE_NEXT(FC_EV_CLOSED, SESS_ST_INIT),
	SA_STATE_NEXT(FC_EV_STOP, SESS_ST_INIT),

	SA_STATE_NAME(SESS_ST_ERROR),
	SA_STATE_NEXT(FC_EV_START, SESS_ST_INIT),
	SA_STATE_NEXT(FC_EV_STOP, SESS_ST_INIT),
	SA_STATE_NEXT(FC_EV_DOWN, SESS_ST_INIT),
	SA_STATE_NEXT(FC_EV_CLOSED, SESS_ST_INIT),
	SA_STATE_END
};

static struct sa_state_table *fc_sess_state_table;
static u_int fc_sess_table_refcnt;

/*
 * Lock session.
 */
static inline void fc_sess_lock(struct fc_sess *sess)
{
}

/*
 * Unlock session without invoking pending events.
 */
static inline void fc_sess_unlock(struct fc_sess *sess)
{
}

#ifdef DEBUG_ASSERTS
/*
 * Check whether session is locked.
 */
static inline int fc_sess_locked(const struct fc_sess *sess)
{
	return 0;
}
#endif /* DEBUG_ASSERTS */

/*
 * Unlock session.
 * This must handle operations that defer because they can't be done
 * with the session lock held.
 */
static inline void fc_sess_unlock_send(struct fc_sess *sess)
{
	struct fc_local_port *lp;
	enum fc_sess_state state = sess->fs_state;

	/*
	 * If the session is in the INIT or ERROR state and the session
	 * has been started, meaning there's an internal reference, and that's
	 * the only reference, handle this unlock specially by releasing that
	 * reference thus deleting the session.  If in READY state and there's
	 * no other reference, start a logout.
	 */
	if (sess->fs_started && sess->fs_refcnt == 1) {
		if (state == SESS_ST_INIT || state == SESS_ST_ERROR) {
			sess->fs_started = 0;
			fc_sess_unlock(sess);
			sa_event_send_deferred(sess->fs_events);
			fc_sess_release(sess);
			return;
		}
		if (state == SESS_ST_READY)
			fc_sess_state_event(sess, FC_EV_STOP);
	}

	/*
	 * Handle local port logon after started with session unlocked.
	 */
	fc_sess_hold(sess);
	lp = sess->fs_local_port;
	if (state == SESS_ST_STARTED &&
	    sess != lp->fl_dns_sess && fc_local_port_test_ready(lp) == 0) {
		fc_sess_unlock(sess);
		sa_event_send_deferred(sess->fs_events);
		fc_local_port_logon(lp, fc_sess_local_port_event, sess);
	} else {
		fc_sess_unlock(sess);
		sa_event_send_deferred(sess->fs_events);
	}
	fc_sess_release(sess);
}

/*
 * Handle next session state after a successful completion.
 */
static void fc_sess_state_event(struct fc_sess *sess, enum fc_event event)
{
	if (event != FC_EV_TIMEOUT)
		sess->fs_retries = 0;
	sa_state_table_step(fc_sess_state_table, &sess->fs_state, event, sess);
}

static void fc_sess_state_enter(struct fc_sess *sess,
				enum fc_sess_state next_state)
{
	sa_state_table_enter(fc_sess_state_table, &sess->fs_state,
			     next_state, FC_EV_ACC, sess);
}

/*
 * Log state transition messages.
 */
static void fc_sess_log(void *sess_arg, const char *msg)
{
	struct fc_sess *sess = sess_arg;

	dprintf("sess to %6x %s", sess->fs_remote_fid, msg);
}

/*
 * Create hash lookup table for sessions.
 */
int fc_sess_table_create(struct fc_virt_fab *vf)
{
	struct sa_hash *tp;

	tp = sa_hash_create(&fc_sess_hash_type, FC_SESS_HASH_SIZE);

	if (!tp)
		return -1;
	if (!fc_sess_state_table) {
		fc_sess_state_table =
		    sa_state_table_alloc("session", fc_sess_state_desc);

		if (!fc_sess_state_table) {
			sa_hash_destroy(tp);
			return -1;
		}
		if (fc_sess_debug)
			sa_state_table_log(fc_sess_state_table, fc_sess_log);
	}
	fc_sess_table_refcnt++;
	vf->vf_sess_by_fids = tp;
	return 0;
}

/*
 * Call a function for all sessions on the fabric.
 * The vf_lock must not be held during the callback.
 *
 * Note that the local port lock isn't needed to traverse the list of
 * local ports or the list of sessions on each local port.
 * fc_local_port_release(), used either here or in the callback,
 * requires the vf_lock, however.
 *
 * Both the outer and inner loop work the same way.  They hold the
 * current and the next element (local port or session) to keep them
 * from being deleted while the lock is given up.  They are guaranteed to
 * remain on the list while held.
 */
static void fc_sess_iterate(struct fc_virt_fab *vf,
			    void (*func) (struct fc_sess *, void *), void *arg)
{
	struct fc_sess *sess;
	struct fc_sess *next;
	struct fc_local_port *lp;
	struct fc_local_port *next_lp;

	fc_virt_fab_lock(vf);
	if (!list_empty(&vf->vf_local_ports)) {
		lp = list_first_entry(&vf->vf_local_ports, struct fc_local_port, fl_list);
		fc_local_port_hold(lp);
		list_for_each_entry_safe(lp, next_lp, &vf->vf_local_ports, fl_list) {
			if (&next_lp->fl_list != &vf->vf_local_ports)
				fc_local_port_hold(next_lp);
			if (!list_empty(&lp->fl_sess_list)) {
				sess = list_first_entry(&lp->fl_sess_list, struct fc_sess, fs_list);
				fc_sess_hold(sess);
				list_for_each_entry_safe(sess, next, &lp->fl_sess_list, fs_list) {
					if (&next->fs_list != &lp->fl_sess_list)
						fc_sess_hold(next);
					fc_virt_fab_unlock(vf);
					(*func) (sess, arg);
					fc_sess_release(sess);
					fc_virt_fab_lock(vf);
				}
			}
			fc_virt_fab_unlock(vf);
			fc_local_port_release(lp);
			fc_virt_fab_lock(vf);
		}
	}
	fc_virt_fab_unlock(vf);
}

static void fc_sess_debug_print(void *sess_arg, void *arg)
{
	struct fc_sess *sess = sess_arg;

	dprintf("fid %6.6x did %6.6x ref %d\n", sess->fs_local_fid,
	       sess->fs_remote_fid, sess->fs_refcnt);

}

/*
 * Remove all sessions in a virtual fabric.
 * This takes care of freeing memory for incoming sessions.
 */
void fc_sess_table_destroy(struct fc_virt_fab *vf)
{
	fc_sess_iterate(vf, fc_sess_delete, NULL);
	fc_virt_fab_lock(vf);
	sa_hash_iterate(vf->vf_sess_by_fids, fc_sess_debug_print, NULL);
	sa_hash_destroy(vf->vf_sess_by_fids);
	vf->vf_sess_by_fids = NULL;
	fc_virt_fab_unlock(vf);
	fc_sess_table_refcnt--;
	if (fc_sess_state_table && fc_sess_table_refcnt == 0) {
		sa_state_table_free(fc_sess_state_table);
		fc_sess_state_table = NULL;
	}
}

/*
 * Create session.
 * If the session already exists, find and hold it.
 */
struct fc_sess *fc_sess_create(struct fc_local_port *lp,
			       struct fc_remote_port *rp)
{
	struct fc_sess *sess;
	struct fc_sess *found;
	struct sa_event_list *events;
	struct fc_virt_fab *vp;
	u_int64_t key;

	sess = zalloc(sizeof(*sess));
	if (sess) {

		events = sa_event_list_alloc();

		if (!events) {
			free(sess);
			sess = NULL;
		} else {
			vp = lp->fl_vf;

			/*
			 * Initialize session even though we might end up
			 * freeing it after getting the lock.
			 * This minimizes lock hold time.
			 */
			memset(sess, 0, sizeof(*sess));
			sess->fs_state = SESS_ST_INIT;
			sess->fs_refcnt = 1;
			sess->fs_sess_id = lp->fl_next_sess_id++;
			sess->fs_events = events;
			sess->fs_remote_port = rp;
			sess->fs_local_port = lp;
			sess->fs_remote_fid = rp->rp_fid;
			sess->fs_local_fid = lp->fl_fid;
			sess->fs_max_payload = lp->fl_max_payload;
			sess->fs_e_d_tov = lp->fl_e_d_tov;
			sess->fs_r_a_tov = lp->fl_r_a_tov;
			sa_timer_init(&sess->fs_timer, fc_sess_timeout, sess);

			rp->rp_sess = sess;
			rp->rp_sess_ready = (sess->fs_state == SESS_ST_READY);

			/*
			 * Since we didn't have the lock while possibly
			 * waiting for memory, check for a simultaneous
			 * creation of the same session.
			 */
			key = fc_sess_key(lp->fl_fid, rp->rp_fid);
			fc_virt_fab_lock(vp);
			found = sa_hash_lookup(vp->vf_sess_by_fids, &key);
			if (found) {
				fc_sess_hold(found);
				fc_virt_fab_unlock(vp);
				free(sess);
				sa_event_list_free(events);
				sess = found;
			} else {
				fc_remote_port_hold(rp);
				fc_local_port_hold(lp);
				sa_hash_insert(vp->vf_sess_by_fids, &key, sess);
				list_add_tail(&sess->fs_list, &lp->fl_sess_list);
				fc_virt_fab_unlock(vp);
			}
		}
	}
	return sess;
}

static void fc_sess_rcu_free(struct fc_sess *sess)
{
	sa_event_list_free(sess->fs_events);
	free(sess);
}

/*
 * Delete the session.
 * Called with the local port lock held, but the virtual fabric lock not held.
 */
static void fc_sess_delete(struct fc_sess *sess, void *arg)
{
	struct fc_local_port *lp;
	struct fc_remote_port *rp;
	struct fc_virt_fab *vp;
	struct fc_sess *found;
	u_int64_t key;

	if (fc_sess_debug)
		dprintf("sess to %6x delete", sess->fs_remote_fid);
	lp = sess->fs_local_port;
	rp = sess->fs_remote_port;
	vp = lp->fl_vf;
	fc_local_port_event_deq(lp, fc_sess_local_port_event, sess);
	key = fc_sess_key(sess->fs_local_fid, sess->fs_remote_fid);

	fc_virt_fab_lock(vp);
	found = sa_hash_lookup_delete(vp->vf_sess_by_fids, &key);
	list_del(&sess->fs_list);			/* under vf_lock */
	fc_virt_fab_unlock(vp);

	sa_timer_cancel(&sess->fs_timer);
	fc_sess_rcu_free(sess);

	fc_remote_port_release(rp);
	fc_local_port_release(lp);
}

void fc_sess_hold(struct fc_sess *sess)
{
	sess->fs_refcnt++;
}

void fc_sess_release(struct fc_sess *sess)
{
	if (!(--sess->fs_refcnt))
		fc_sess_delete(sess, NULL);
}

/*
 * Start the session login state machine.
 * Set it to wait for the local_port to be ready if it isn't.
 */
void fc_sess_start(struct fc_sess *sess)
{
	fc_sess_lock(sess);
	if (sess->fs_started == 0) {
		sess->fs_started = 1;
		fc_sess_hold(sess);	/* internal hold while active */
	}
	if (sess->fs_state == SESS_ST_INIT || sess->fs_state == SESS_ST_ERROR)
		fc_sess_state_event(sess, FC_EV_START);
	fc_sess_unlock_send(sess);
}

/*
 * Stop the session - log it off.
 */
void fc_sess_stop(struct fc_sess *sess)
{
	fc_sess_lock(sess);
	fc_sess_state_event(sess, FC_EV_STOP);
	fc_sess_unlock_send(sess);
}

/*
 * Reset the session - assume it is logged off.  Used after fabric logoff.
 * The local port code takes care of resetting the exchange manager.
 */
void fc_sess_reset(struct fc_sess *sess)
{
	struct fc_local_port *lp;
	struct fc_virt_fab *vp;
	struct fc_sess *found;
	u_int64_t key;
	u_int started;
	u_int held;

	if (fc_sess_debug)
		dprintf("sess to %6x reset", sess->fs_remote_fid);
	fc_sess_lock(sess);
	started = sess->fs_started;
	held = sess->fs_plogi_held;
	sess->fs_started = 0;
	sess->fs_plogi_held = 0;
	sess->fs_remote_port->rp_sess_ready = 0;

	lp = sess->fs_local_port;
	if (lp->fl_fid != sess->fs_local_fid) {
		key = fc_sess_key(sess->fs_local_fid, sess->fs_remote_fid);
		vp = lp->fl_vf;
		found = sa_hash_lookup_delete(vp->vf_sess_by_fids, &key);
		sess->fs_local_fid = lp->fl_fid;
		key = fc_sess_key(sess->fs_local_fid, sess->fs_remote_fid);
		sa_hash_insert(vp->vf_sess_by_fids, &key, sess);
	}
	fc_sess_state_enter(sess, SESS_ST_INIT);
	fc_sess_unlock_send(sess);
	if (started)
		fc_sess_release(sess);
	if (held)
		fc_sess_release(sess);
}

/*
 * Reset all sessions for a local port session list.
 * The vf_lock protects the list.
 * Don't hold the lock over the reset call, instead hold the session
 * as well as the next session on the list.
 * Holding the session must guarantee it'll stay on the same list.
 */
void fc_sess_reset_list(struct fc_virt_fab *vp, struct list_head *sess_head)
{
	struct fc_sess *sess;
	struct fc_sess *next;

	fc_virt_fab_lock(vp);
	if (!list_empty(sess_head)) {
		sess = list_first_entry(sess_head, struct fc_sess, fs_list);
		fc_sess_hold(sess);
		list_for_each_entry_safe(sess, next, sess_head, fs_list) {
			if (&next->fs_list != sess_head)
				fc_sess_hold(next);	/* hold next session */
			fc_virt_fab_unlock(vp);
			fc_sess_reset(sess);
			fc_sess_release(sess);
			fc_virt_fab_lock(vp);
		}
	}
	fc_virt_fab_unlock(vp);
}

/*
 * Get a sequence to use the session.
 * External users shouldn't do this until notified that the session is ready.
 * Internally, it can be done anytime after the local_port is ready.
 */
struct fc_seq *fc_sess_seq_alloc(struct fc_sess *sess,
				 void (*recv) (struct fc_seq *,
					       struct fc_frame *, void *),
				 void (*errh) (enum fc_event, void *),
				 void *arg)
{
	struct fc_seq *sp;
	struct fc_exch *ep;
	struct fc_local_port *lp;

	lp = sess->fs_local_port;
	sp = fc_seq_start_exch(lp->fl_vf->vf_exch_mgr,
			       recv, errh, arg, sess->fs_local_fid,
			       sess->fs_remote_fid);
	if (sp) {
		ep = fc_seq_exch(sp);
		ep->ex_port = lp->fl_port;
		ep->ex_max_payload = sess->fs_max_payload;
	}
	return sp;
}

/*
 * Send a frame on a session using a new exchange.
 * External users shouldn't do this until notified that the session is ready.
 * Internally, it can be done anytime after the local_port is ready.
 */
int fc_sess_send_req(struct fc_sess *sess, struct fc_frame *fp,
		     void (*recv) (struct fc_seq *, struct fc_frame *, void *),
		     void (*errh) (enum fc_event, void *), void *arg)
{
	struct fc_frame_header *fh;
	struct fc_seq *sp;
	struct fc_local_port *lp;
	int rc;

	fh = fc_frame_header_get(fp);

	sp = fc_sess_seq_alloc(sess, recv, errh, arg);
	if (sp) {
		sp->seq_f_ctl |= FC_FC_SEQ_INIT;
		lp = sess->fs_local_port;
		if (lp->fl_e_d_tov)
			fc_exch_timer_set(fc_seq_exch(sp), lp->fl_e_d_tov);
		rc = fc_seq_send(sp, fp);
	} else {
		fc_frame_free(fp);
		rc = ENOMEM;
	}
	return rc;
}

static void fc_sess_local_port_event(int event, void *sess_arg)
{
	struct fc_sess *sess = sess_arg;

	fc_sess_lock(sess);
	fc_sess_state_event(sess, event);
	fc_sess_unlock_send(sess);
}

static void fc_sess_enter_started(struct fc_sess *sess)
{
	struct fc_local_port *lp;

	/*
	 * If the local port is already logged on, advance to next state.
	 * Otherwise the local port will be logged on by fc_sess_unlock().
	 */
	lp = sess->fs_local_port;
	if (sess == lp->fl_dns_sess || fc_local_port_test_ready(lp))
		fc_sess_state_event(sess, FC_EV_ACC);
}

/*
 * Timeout handler for retrying after allocation failures.
 */
static void fc_sess_timeout(void *sess_arg)
{
	fc_sess_state_event((struct fc_sess *)sess_arg, FC_EV_TIMEOUT);
}

/*
 * Handle retry for allocation failure via timeout.
 */
static void fc_sess_retry(struct fc_sess *sess)
{
	const char *state;
	struct fc_local_port *lp;

	state = sa_state_name(fc_sess_state_table, sess->fs_state);
	lp = sess->fs_local_port;
	if (sess->fs_retries == 0)
		dprintf("sess %6x alloc failure in state %s - will retry",
		       sess->fs_remote_fid, state);
	if (sess->fs_retries < lp->fl_retry_limit) {
		sess->fs_retries++;
		sa_timer_set(&sess->fs_timer, sess->fs_e_d_tov * 1000);
	} else {
		dprintf("sess %6x alloc failure in state %s - retries exhausted",
		       sess->fs_remote_fid, state);
		fc_sess_state_event(sess, FC_EV_RJT);
	}
}

/*
 * Handle error event from a sequence issued by the state machine.
 */
static void fc_sess_error(enum fc_event event, void *sess_arg)
{
	struct fc_sess *sess = sess_arg;

	fc_sess_lock(sess);
	if (event == FC_EV_TIMEOUT &&
	    sess->fs_retries++ >= sess->fs_local_port->fl_retry_limit)
		event = FC_EV_RJT;
	if (fc_sess_debug)
		dprintf("event %s retries %d",
		       sa_state_event_name(fc_sess_state_table, event),
		       sess->fs_retries);
	fc_sess_state_event(sess_arg, event);
	fc_sess_unlock_send(sess);
}

/*
 * Handle incoming ELS PLOGI response.
 * Save parameters of target.  Finish exchange.
 */
static void fc_sess_plogi_recv_resp(struct fc_seq *sp, struct fc_frame *fp,
				    void *sess_arg)
{
	struct fc_sess *sess = sess_arg;
	struct fc_els_ls_rjt *rjp;
	struct fc_els_flogi *plp;
	u_int tov;
	uint16_t csp_seq;
	uint16_t cssp_seq;
	u_int op;

	op = fc_frame_payload_op(fp);
	fc_sess_lock(sess);
	if (op == ELS_LS_ACC &&
	    (plp = fc_frame_payload_get(fp, sizeof(*plp))) != NULL) {
		fc_remote_port_set_name(sess->fs_remote_port,
					net64_get(&plp->fl_wwpn),
					net64_get(&plp->fl_wwnn));
		tov = net32_get(&plp->fl_csp.sp_e_d_tov);
		if (net16_get(&plp->fl_csp.sp_features) & FC_SP_FT_EDTR)
			tov /= 1000;
		if (tov > sess->fs_e_d_tov)
			sess->fs_e_d_tov = tov;
		csp_seq = net16_get(&plp->fl_csp.sp_tot_seq);
		cssp_seq = net16_get(&plp->fl_cssp[3 - 1].cp_con_seq);
		if (cssp_seq < csp_seq)
			csp_seq = cssp_seq;
		sess->fs_max_seq = csp_seq;
		fc_sess_state_event(sess, FC_EV_ACC);
	} else {
		if (fc_sess_debug) {
			eprintf("bad PLOGI response");
/* 			fc_print_frame_hdr((char *)__FUNCTION__, fp); */
		}
		rjp = fc_frame_payload_get(fp, sizeof(*rjp));
#if 0				/* XXX */
		if (op == ELS_LS_RJT && rjp != NULL &&
		    rjp->er_reason == ELS_RJT_INPROG)
			fc_sess_state_event(sess, FC_EV_TIMEOUT);
/* XXX not right either.   Should have a wait state ... retry after a bit. */
		else
#endif
			fc_sess_state_event(sess, FC_EV_RJT);
	}
	fc_sess_unlock_send(sess);
	fc_frame_free(fp);
}

/*
 * Send ELS (extended link service) PLOGI request to peer.
 */
static void fc_sess_enter_plogi(struct fc_sess *sess)
{
	struct fc_frame *fp;
	struct fc_els_flogi *rp;

	sess->fs_max_payload = sess->fs_local_port->fl_max_payload;
	fp = fc_frame_alloc(sess->fs_local_port->fl_port, sizeof(*rp));
	if (!fp) {
		fc_sess_retry(sess);
		return;
	}
	rp = fc_frame_payload_get(fp, sizeof(*rp));
	fc_local_port_flogi_fill(sess->fs_local_port, rp, ELS_PLOGI);
	sess->fs_e_d_tov = sess->fs_local_port->fl_e_d_tov;
	fc_frame_setup(fp, FC_RCTL_ELS_REQ, FC_TYPE_ELS);
	if (fc_sess_send_req(sess, fp, fc_sess_plogi_recv_resp,
			     fc_sess_error, sess)) {
		fc_sess_retry(sess);
	}
}

/*
 * Handle incoming ELS response.
 */
static void fc_sess_els_recv_resp(struct fc_seq *sp, struct fc_frame *fp,
				  void *sess_arg)
{
	struct fc_sess *sess = sess_arg;
	u_char op;

	fc_sess_lock(sess);
	op = fc_frame_payload_op(fp);
	if (op == ELS_LS_ACC) {

		/*
		 * For PRLI, get the remote port's service parameter flags.
		 */
		if (sess->fs_state == SESS_ST_PRLI) {
			struct {
				struct fc_els_prli prli;
				struct fc_els_spp spp;
			} *pp;

			pp = fc_frame_payload_get(fp, sizeof(*pp));
			if (pp && pp->prli.prli_spp_len >= sizeof(pp->spp)) {
				sess->fs_remote_port->rp_fcp_parm =
				    net32_get(&pp->spp.spp_params);
			}
		}
		fc_sess_state_event(sess, FC_EV_ACC);
	} else {
		eprintf("bad ELS response\n");
/* 		fc_print_frame_hdr((char *)__FUNCTION__, fp);	/\* XXX *\/ */
		fc_sess_state_event(sess, FC_EV_RJT);
	}
	fc_sess_unlock_send(sess);
	fc_frame_free(fp);
}

/*
 * Send ELS PRLI request to target.
 */
static void fc_sess_enter_prli(struct fc_sess *sess)
{
	struct {
		struct fc_els_prli prli;
		struct fc_els_spp spp;
	} *pp;
	struct fc_frame *fp;

	/*
	 * Special case if session is for name server or any other
	 * well-known address:  Skip the PRLI step.
	 * This should be made more general, possibly moved to the FCP layer.
	 */
	if (sess->fs_remote_fid >= FC_FID_DOM_MGR) {
		fc_sess_state_enter(sess, SESS_ST_READY);
		return;
	}
	fp = fc_frame_alloc(sess->fs_local_port->fl_port, sizeof(*pp));
	if (!fp) {
		fc_sess_retry(sess);
		return;
	}
	pp = fc_frame_payload_get(fp, sizeof(*pp));
	memset(pp, 0, sizeof(*pp));
	pp->prli.prli_cmd = ELS_PRLI;
	pp->prli.prli_spp_len = sizeof(struct fc_els_spp);
	net16_put(&pp->prli.prli_len, sizeof(*pp));
	pp->spp.spp_type = FC_TYPE_FCP;
	pp->spp.spp_flags = FC_SPP_EST_IMG_PAIR;
	net32_put(&pp->spp.spp_params, sess->fs_remote_port->rp_local_fcp_parm);
	fc_frame_setup(fp, FC_RCTL_ELS_REQ, FC_TYPE_ELS);
	if (fc_sess_send_req(sess, fp, fc_sess_els_recv_resp,
			     fc_sess_error, sess)) {
		fc_sess_retry(sess);
	}
}

/*
 * Handle incoming ELS response.
 * Many targets don't seem to support this.
 */
static void fc_sess_els_rtv_resp(struct fc_seq *sp, struct fc_frame *fp,
				 void *sess_arg)
{
	struct fc_sess *sess = sess_arg;
	u_char op;

	fc_sess_lock(sess);
	op = fc_frame_payload_op(fp);
	if (op == ELS_LS_ACC) {
		struct fc_els_rtv_acc *rtv;
		uint32_t toq;
		uint32_t tov;

		rtv = fc_frame_payload_get(fp, sizeof(*rtv));
		if (rtv) {
			toq = net32_get(&rtv->rtv_toq);
			tov = net32_get(&rtv->rtv_r_a_tov);
			if (tov == 0)
				tov = 1;
			sess->fs_r_a_tov = tov;
			tov = net32_get(&rtv->rtv_e_d_tov);
			if (toq & FC_ELS_RTV_EDRES)
				tov /= 1000000;
			if (tov == 0)
				tov = 1;
			sess->fs_e_d_tov = tov;
		}
		fc_sess_state_event(sess, FC_EV_ACC);
	} else {
		fc_sess_state_event(sess, FC_EV_RJT);
	}
	fc_sess_unlock_send(sess);
	fc_frame_free(fp);
}

/*
 * Send ELS RTV (Request Timeout Value) request to remote port.
 */
static void fc_sess_enter_rtv(struct fc_sess *sess)
{
	struct fc_els_rtv *rtv;
	struct fc_frame *fp;

	fp = fc_frame_alloc(sess->fs_local_port->fl_port, sizeof(*rtv));
	if (!fp) {
		fc_sess_retry(sess);
		return;
	}
	rtv = fc_frame_payload_get(fp, sizeof(*rtv));
	memset(rtv, 0, sizeof(*rtv));
	rtv->rtv_cmd = ELS_RTV;
	fc_frame_setup(fp, FC_RCTL_ELS_REQ, FC_TYPE_ELS);
	if (fc_sess_send_req(sess, fp, fc_sess_els_rtv_resp,
			     fc_sess_error, sess)) {
		fc_sess_retry(sess);
	}
}

/*
 * Register event handler.
 * Session locks are not needed, the sa_event mechanism has its own locks.
 */
struct sa_event *fc_sess_event_enq(struct fc_sess *sess,
				   sa_event_handler_t handler, void *arg)
{
	return sa_event_enq(sess->fs_events, handler, arg);
}

/*
 * Unregister event handler.
 * Session locks are not needed, the sa_event mechanism has its own locks.
 */
void fc_sess_event_deq(struct fc_sess *sess, sa_event_handler_t handler,
		       void *arg)
{
	sa_event_deq(sess->fs_events, handler, arg);
}

static void fc_sess_enter_ready(struct fc_sess *sess)
{
	sa_event_call_cancel(sess->fs_events, FC_EV_CLOSED);
	sa_event_call_cancel(sess->fs_events, FC_EV_RJT);
	sa_event_call_defer(sess->fs_events, FC_EV_READY);
}

static void fc_sess_enter_init(struct fc_sess *sess)
{
	sa_event_call_cancel(sess->fs_events, FC_EV_READY);
	sa_event_call_cancel(sess->fs_events, FC_EV_RJT);
	sa_event_call_defer(sess->fs_events, FC_EV_CLOSED);
}

static void fc_sess_enter_error(struct fc_sess *sess)
{
	sa_event_call_cancel(sess->fs_events, FC_EV_READY);
	sa_event_call_cancel(sess->fs_events, FC_EV_CLOSED);
	sa_event_call_defer(sess->fs_events, FC_EV_RJT);
}

static void fc_sess_enter_logo(struct fc_sess *sess)
{
	struct fc_frame *fp;
	struct fc_els_logo *logo;
	struct fc_local_port *lp;

	lp = sess->fs_local_port;
	fp = fc_frame_alloc(lp->fl_port, sizeof(*logo));
	if (!fp) {
		fc_sess_retry(sess);
		return;
	}
	logo = fc_frame_payload_get(fp, sizeof(*logo));
	memset(logo, 0, sizeof(*logo));
	logo->fl_cmd = ELS_LOGO;
	net24_put(&logo->fl_n_port_id, lp->fl_fid);
	net64_put(&logo->fl_n_port_wwn, lp->fl_port_wwn);

	fc_frame_setup(fp, FC_RCTL_ELS_REQ, FC_TYPE_ELS);
	if (fc_sess_send_req(sess, fp, fc_sess_els_recv_resp,
			     fc_sess_error, sess)) {
		fc_sess_retry(sess);
	}
}

/*
 * Get local port.
 */
struct fc_local_port *fc_sess_get_local_port(struct fc_sess *sess)
{
	return sess->fs_local_port;
}

/*
 * Get remote port.
 */
struct fc_remote_port *fc_sess_get_remote_port(struct fc_sess *sess)
{
	return sess->fs_remote_port;
}

/*
 * Get local FC_ID.
 */
fc_fid_t fc_sess_get_sid(struct fc_sess *sess)
{
	return sess->fs_local_fid;
}

/*
 * Get remote FC_ID.
 */
fc_fid_t fc_sess_get_did(struct fc_sess *sess)
{
	return sess->fs_remote_fid;
}

/*
 * Get max payload size.
 */
u_int fc_sess_get_max_payload(struct fc_sess *sess)
{
	return sess->fs_max_payload;
}

/*
 * Get virtual fabric pointer.
 */
struct fc_virt_fab *fc_sess_get_virt_fab(struct fc_sess *sess)
{
	return sess->fs_local_port->fl_vf;
}

/*
 * Get E_D_TOV.
 */
u_int fc_sess_get_e_d_tov(struct fc_sess *sess)
{
	return sess->fs_e_d_tov;
}

/*
 * Get R_A_TOV.
 */
u_int fc_sess_get_r_a_tov(struct fc_sess *sess)
{
	return sess->fs_r_a_tov;
}

int fc_sess_is_ready(struct fc_sess *sess)
{
	return sess->fs_state == SESS_ST_READY;
}

/*
 * Handle a request received by the exchange manager for the session.
 * This may be an entirely new session, or a PLOGI or LOGO for an existing one.
 * This will free the frame.
 */
void fc_sess_recv_req(struct fc_seq *sp, struct fc_frame *fp, void *sess_arg)
{
	struct fc_sess *sess = sess_arg;
	struct fc_frame_header *fh;
	u_char op;

	fh = fc_frame_header_get(fp);
	op = fc_frame_payload_op(fp);

	if (fh->fh_r_ctl == FC_RCTL_ELS_REQ && fh->fh_type == FC_TYPE_ELS) {
		switch (op) {
		case ELS_PLOGI:
			fc_sess_recv_plogi_req(sess, sp, fp);
			break;
		case ELS_PRLI:
			fc_sess_recv_prli_req(sess, sp, fp);
			break;
		case ELS_PRLO:
			fc_sess_recv_prlo_req(sess, sp, fp);
			break;
		case ELS_LOGO:
			fc_sess_recv_logo_req(sess, sp, fp);
			break;
		default:
			fc_seq_ls_rjt(sp, ELS_RJT_UNSUP, ELS_EXPL_NONE);
			fc_frame_free(fp);
			break;
		}
	} else {
		fc_port_ingress(sess->fs_local_port->fl_port, fp);
	}
}

/*
 * Handle incoming PLOGI request.
 */
static void fc_sess_recv_plogi_req(struct fc_sess *sess,
				   struct fc_seq *sp, struct fc_frame *rx_fp)
{
	struct fc_frame *fp = rx_fp;
	struct fc_frame_header *fh;
	struct fc_remote_port *rp;
	struct fc_local_port *lp;
	struct fc_els_flogi *pl;
	fc_fid_t sid;
	fc_wwn_t wwpn;
	fc_wwn_t wwnn;
	enum fc_els_rjt_reason reject = 0;

	fh = fc_frame_header_get(fp);
	sid = net24_get(&fh->fh_s_id);
	pl = fc_frame_payload_get(fp, sizeof(*pl));
	if (!pl) {
		eprintf("incoming PLOGI from %x too short", sid);
		/* XXX TBD: send reject? */
		fc_frame_free(fp);
		return;
	}
	wwpn = net64_get(&pl->fl_wwpn);
	wwnn = net64_get(&pl->fl_wwnn);
	fc_sess_lock(sess);
	rp = sess->fs_remote_port;
	lp = sess->fs_local_port;

	/*
	 * If the session was just created, possibly due to the incoming PLOGI,
	 * set the state appropriately and accept the PLOGI.
	 *
	 * If we had also sent a PLOGI, and if the received PLOGI is from a
	 * higher WWPN, we accept it, otherwise an LS_RJT is sent with reason
	 * "command already in progress".
	 *
	 * XXX TBD: If the session was ready before, the PLOGI should result in
	 * all outstanding exchanges being reset.
	 */
	switch (sess->fs_state) {
	case SESS_ST_INIT:
		if (!lp->fl_prli_accept) {
			/*
			 * The upper level protocol isn't expecting logins.
			 */
			dprintf("incoming PLOGI from %6x wwpn %llx state INIT "
			       "- reject\n", sid, wwpn);
			reject = ELS_RJT_UNSUP;
		} else {
			if (fc_sess_debug)
				dprintf("incoming PLOGI from %6x "
				       "wwpn %llx state INIT "
				       "- accept\n", sid, wwpn);
		}
		break;

	case SESS_ST_STARTED:
		/*
		 * we'll only accept a login if the port name
		 * matches or was unknown.
		 */
		if (rp->rp_port_wwn != 0 && rp->rp_port_wwn != wwpn) {
			dprintf("incoming PLOGI from name %llx expected %llx\n",
			       wwpn, rp->rp_port_wwn);
			reject = ELS_RJT_UNAB;
		}
		break;
	case SESS_ST_PLOGI:
		if (fc_sess_debug)
			dprintf("incoming PLOGI from %x in PLOGI state %d",
			       sid, sess->fs_state);
		if (wwpn < lp->fl_port_wwn)
			reject = ELS_RJT_INPROG;
		break;
	case SESS_ST_PRLI:
	case SESS_ST_ERROR:
	case SESS_ST_READY:
		if (fc_sess_debug)
			dprintf("incoming PLOGI from %x in logged-in state %d "
			       "- ignored for now", sid, sess->fs_state);
		/* XXX TBD - should reset */
		break;
	case SESS_ST_NONE:
	default:
		if (fc_sess_debug)
			dprintf("incoming PLOGI from %x in unexpected state %d",
			       sid, sess->fs_state);
		break;
	}

	if (reject) {
		fc_seq_ls_rjt(sp, reject, ELS_EXPL_NONE);
		fc_frame_free(fp);
	} else if ((fp = fc_frame_alloc(lp->fl_port, sizeof(*pl))) == NULL) {
		fp = rx_fp;
		fc_seq_ls_rjt(sp, ELS_RJT_UNAB, ELS_EXPL_NONE);
		fc_frame_free(fp);
	} else {
		sp = fc_seq_start_next(sp);
		fc_frame_free(rx_fp);
		fc_remote_port_set_name(rp, wwpn, wwnn);

		/*
		 * Get session payload size from incoming PLOGI.
		 */
		sess->fs_max_payload = (uint16_t)
		    fc_local_port_get_payload_size(pl, lp->fl_max_payload);
		pl = fc_frame_payload_get(fp, sizeof(*pl));
		fc_local_port_flogi_fill(lp, pl, ELS_LS_ACC);

		/*
		 * Send LS_ACC.  If this fails, the originator should retry.
		 */
		fc_seq_send_last(sp, fp, FC_RCTL_ELS_REP, FC_TYPE_ELS);
		if (sess->fs_state == SESS_ST_PLOGI)
			fc_sess_state_enter(sess, SESS_ST_PRLI);
		else
			fc_sess_state_enter(sess, SESS_ST_PLOGI_RECV);
		fc_sess_hold(sess);	/* represents login */
		sess->fs_plogi_held = 1;
	}
	fc_sess_unlock_send(sess);
}

/*
 * Handle incoming PRLI request.
 */
static void fc_sess_recv_prli_req(struct fc_sess *sess,
				  struct fc_seq *sp, struct fc_frame *rx_fp)
{
	struct fc_frame *fp;
	struct fc_frame_header *fh;
	struct fc_local_port *lp;
	struct fc_remote_port *rp;
	struct {
		struct fc_els_prli prli;
		struct fc_els_spp spp;
	} *pp;
	struct fc_els_spp *rspp;	/* request service param page */
	struct fc_els_spp *spp;	/* response spp */
	u_int len;
	u_int plen;
	enum fc_els_rjt_reason reason = ELS_RJT_UNAB;
	enum fc_els_rjt_explan explan = ELS_EXPL_NONE;
	enum fc_els_spp_resp resp;

	fh = fc_frame_header_get(rx_fp);
	lp = sess->fs_local_port;
	switch (sess->fs_state) {
	case SESS_ST_PLOGI_RECV:
	case SESS_ST_PRLI:
	case SESS_ST_READY:
		if (lp->fl_prli_accept &&
		    (*lp->fl_prli_accept) (lp, sess->fs_remote_port,
					   lp->fl_prli_cb_arg) == 0) {
			reason = ELS_RJT_NONE;
		}
		break;
	default:
		break;
	}
	len = rx_fp->fr_len - sizeof(*fh);
	pp = fc_frame_payload_get(rx_fp, sizeof(*pp));
	if (pp == NULL) {
		reason = ELS_RJT_PROT;
		explan = ELS_EXPL_INV_LEN;
	} else {
		plen = net16_get(&pp->prli.prli_len);
		if ((plen % 4) != 0 || plen > len) {
			reason = ELS_RJT_PROT;
			explan = ELS_EXPL_INV_LEN;
		} else if (plen < len) {
			len = plen;
		}
		plen = pp->prli.prli_spp_len;
		if ((plen % 4) != 0 || plen < sizeof(*spp) ||
		    plen > len || len < sizeof(*pp)) {
			reason = ELS_RJT_PROT;
			explan = ELS_EXPL_INV_LEN;
		}
		rspp = &pp->spp;
	}
	if (reason != ELS_RJT_NONE ||
	    (fp = fc_frame_alloc(lp->fl_port, len)) == NULL) {
		fc_seq_ls_rjt(sp, reason, explan);
	} else {
		sp = fc_seq_start_next(sp);
		pp = fc_frame_payload_get(fp, len);
		memset(pp, 0, len);
		pp->prli.prli_cmd = ELS_LS_ACC;
		pp->prli.prli_spp_len = plen;
		net16_put(&pp->prli.prli_len, len);
		len -= sizeof(struct fc_els_prli);

		/*
		 * Go through all the service parameter pages and build
		 * response.  If plen indicates longer SPP than standard,
		 * use that.  The entire response has been pre-cleared above.
		 */
		spp = &pp->spp;
		while (len >= plen) {
			spp->spp_type = rspp->spp_type;
			spp->spp_type_ext = rspp->spp_type_ext;
			spp->spp_flags = rspp->spp_flags & FC_SPP_EST_IMG_PAIR;
			resp = FC_SPP_RESP_ACK;
			if (rspp->spp_flags & FC_SPP_RPA_VAL)
				resp = FC_SPP_RESP_NO_PA;
			switch (rspp->spp_type) {
			case 0:	/* common to all FC-4 types */
				break;
			case FC_TYPE_FCP:
				rp = sess->fs_remote_port;
				rp->rp_fcp_parm = net32_get(&rspp->spp_params);
				net32_put(&spp->spp_params,
					  rp->rp_local_fcp_parm);
				break;
			default:
				resp = FC_SPP_RESP_INVL;
				break;
			}
			spp->spp_flags |= resp;
			len -= plen;
			rspp = (struct fc_els_spp *)((char *)rspp + plen);
			spp = (struct fc_els_spp *)((char *)spp + plen);
		}

		/*
		 * Send LS_ACC.  If this fails, the originator should retry.
		 */
		fc_seq_send_last(sp, fp, FC_RCTL_ELS_REP, FC_TYPE_ELS);

		/*
		 * Get lock and re-check state.
		 */
		fc_sess_lock(sess);
		switch (sess->fs_state) {
		case SESS_ST_PLOGI_RECV:
		case SESS_ST_PRLI:
			fc_sess_state_enter(sess, SESS_ST_READY);
			break;
		case SESS_ST_READY:
			break;
		default:
			break;
		}
		fc_sess_unlock_send(sess);
	}
	fc_frame_free(rx_fp);
}

/*
 * Handle incoming PRLO request.
 */
static void fc_sess_recv_prlo_req(struct fc_sess *sess, struct fc_seq *sp,
				  struct fc_frame *fp)
{
	struct fc_frame_header *fh;

	fh = fc_frame_header_get(fp);
	dprintf("incoming PRLO from %x state %d",
	       net24_get(&fh->fh_s_id), sess->fs_state);
	fc_seq_ls_rjt(sp, ELS_RJT_UNAB, ELS_EXPL_NONE);
	fc_frame_free(fp);
}

/*
 * Handle incoming LOGO request.
 */
static void fc_sess_recv_logo_req(struct fc_sess *sess, struct fc_seq *sp,
				  struct fc_frame *fp)
{
	struct fc_frame_header *fh;
	u_int held;

	fh = fc_frame_header_get(fp);
	if (fc_sess_debug)
		dprintf("incoming LOGO from %x state %s %s",
			net24_get(&fh->fh_s_id),
			sa_state_name(fc_sess_state_table, sess->fs_state),
			sess->fs_started ? "started" : "not started");
	fc_sess_lock(sess);
	fc_sess_state_event(sess, FC_EV_CLOSED);
	held = sess->fs_plogi_held;
	sess->fs_plogi_held = 0;
	fc_sess_unlock_send(sess);
	if (held)
		fc_sess_release(sess);
	fc_seq_ls_acc(sp);
	fc_frame_free(fp);
}

static int fc_sess_match(sa_hash_key_t key, void *sess_arg)
{
	struct fc_sess *sess = sess_arg;

	return *(u_int64_t *) key ==
	    fc_sess_key(sess->fs_local_fid, sess->fs_remote_fid);
}

static u_int32_t fc_sess_hash(sa_hash_key_t keyp)
{
	u_int64_t key = *(u_int64_t *) keyp;

	return (u_int32_t) ((key >> 20) ^ key);
}

/*
 * Lookup or create a new session.
 * Returns with the session held.
 */
struct fc_sess *fc_sess_lookup_create(struct fc_local_port *lp,
				      fc_fid_t fid, fc_wwn_t wwpn)
{
	struct fc_virt_fab *vp;
	struct fc_remote_port *rp;
	struct fc_sess *sess;
	u_int64_t key;

	vp = lp->fl_vf;

	/*
	 * Look for the source as a remote port in the existing session table.
	 */
	key = fc_sess_key(lp->fl_fid, fid);
	sess = sa_hash_lookup(vp->vf_sess_by_fids, &key);

	/*
	 * Create new session if we didn't find one.
	 */
	if (!sess) {
		rp = fc_remote_port_lookup_create(vp, fid, wwpn, 0);
		if (rp) {
			sess = fc_sess_create(lp, rp);	/* holds remote port */
			fc_remote_port_release(rp);
		}
	} else {
		fc_sess_hold(sess);
	}
	return sess;
}

struct fc_sess_disp_arg {
	char *da_buf;
	size_t da_len;
	size_t da_off;
};

/*
 * Print session state for debugging.
 */
static void fc_sess_disp_one(struct fc_sess *sess, void *arg)
{
	struct fc_sess_disp_arg *ap = arg;
	struct fc_local_port *lp;
	struct fc_remote_port *rp;

	lp = sess->fs_local_port;
	rp = sess->fs_remote_port;
	if (ap->da_off < ap->da_len) {
		ap->da_off += snprintf(ap->da_buf + ap->da_off,
				       ap->da_len - ap->da_off,
				       "sess %u ref %u state %d %s\n"
				       "\tlocal  fid %6x "
				       "wwpn %16.16llx wwnn %16.16llx\n"
				       "\tremote fid %6x "
				       "wwpn %16.16llx wwnn %16.16llx\n",
				       sess->fs_sess_id,
				       sess->fs_refcnt,
				       sess->fs_state,
				       sa_state_name(fc_sess_state_table,
						     sess->fs_state),
				       sess->fs_local_fid, lp->fl_port_wwn,
				       lp->fl_node_wwn, sess->fs_remote_fid,
				       rp->rp_port_wwn, rp->rp_node_wwn);
	}
}

/*
 * Print session state for debugging.
 */
size_t fc_sess_disp(struct fc_sess *sess, char *buf, size_t len)
{
	struct fc_sess_disp_arg arg;

	arg.da_buf = buf;
	arg.da_len = len;
	arg.da_off = 0;
	fc_sess_disp_one(sess, &arg);
	return arg.da_off;
}

/*
 * Supply session states for entire virtual fabric for debugging.
 */
size_t fc_sess_disp_all(struct fc_virt_fab *vf, char *buf, size_t len)
{
	struct fc_sess_disp_arg arg;

	arg.da_buf = buf;
	arg.da_len = len;
	arg.da_off = 0;
	fc_sess_iterate(vf, fc_sess_disp_one, &arg);
	return arg.da_off;
}
