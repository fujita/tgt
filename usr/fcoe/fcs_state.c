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

#include "fc_types.h"
#include "fc_frame.h"
#include "fc_port.h"
#include "fc_virt_fab.h"
#include "fc_local_port.h"
#include "fc_remote_port.h"
#include "fc_exch.h"
#include "fc_sess.h"
#include "fc_disc_targ.h"
#include "fc_event.h"
#include "fc_ils.h"
#include "fc_fcp.h"
#include "fcs_state.h"
#include "fcs_state_impl.h"
#define fcs_ev_add(sp, type, buf, len)
#define fcs_ev_destroy()
#define	fcs_ev_els NULL

static int fcs_debug;		/* set non-zero to get debug messages */

static void fcs_recv_req(void *, struct fc_frame *);
static void fcs_local_port_event(int, void *);
static int fcs_local_port_prli_accept(struct fc_local_port *,
				      struct fc_remote_port *, void *);
static void fcs_add_remote(void *, struct fc_remote_port *, enum fc_event);
static void fcs_sess_event(int, void *);
static void fcs_port_event(int, void *);

void fcs_module_init(void)
{
	fc_exch_module_init();
}

void fcs_module_exit(void)
{
	fc_exch_module_exit();
	fcs_ev_destroy();
}

static void fcs_nop(void)
{
}

/*
 * Allocate the FCS state.
 * Called once per instance of the OpenFC driver.
 */
struct fcs_state *fcs_create(struct fcs_create_args *ap)
{
	struct fcs_state *sp;
	struct fc_port *inner_port;
	struct fc_port *outer_port;
	size_t mfs;

	sp = zalloc(sizeof(*sp));
	if (!sp)
		return NULL;

	sp->fs_vf = fc_virt_fab_alloc(0, FC_CLASS_3,
				      ap->fca_min_xid, ap->fca_max_xid);

	if (!sp->fs_vf)
		goto error;

	sp->fs_args = *ap;	/* struct copy of args */
	if (!sp->fs_args.fca_remote_port_state_change)
		sp->fs_args.fca_remote_port_state_change =
		    (void (*)(void *, struct fc_remote_port *))fcs_nop;
	if (!sp->fs_args.fca_disc_done)
		sp->fs_args.fca_disc_done = (void (*)(void *))fcs_nop;

	inner_port = fc_port_alloc();

	if (!inner_port)
		goto error;
	sp->fs_inner_port = inner_port;
	outer_port = ap->fca_port;
	mfs = fc_port_get_max_frame_size(outer_port);
	if (mfs < FC_MIN_MAX_PAYLOAD) {
		eprintf("port max frame size only %zu (0x%zx) bytes - "
		       "setting to %d", mfs, mfs, FC_MIN_MAX_PAYLOAD);
		mfs = 1024;
	} else if (mfs > FC_MAX_PAYLOAD + sizeof(struct fc_frame_header)) {
		eprintf("port max frame size too large: %zu (0x%zx) bytes\n",
		       mfs, mfs);
		mfs = FC_MAX_PAYLOAD + sizeof(struct fc_frame_header);
	}
	fc_port_set_max_frame_size(inner_port, mfs);
	fc_port_set_ingress(inner_port, fcs_recv_req, sp);
	fc_port_set_egress(inner_port, (int (*)(void *, struct fc_frame *))
			   fc_port_egress, outer_port);
	fc_port_set_frame_alloc(inner_port, outer_port->np_frame_alloc);
	fc_port_set_ingress(outer_port,
			    (void (*)(void *, struct fc_frame *))fcs_recv, sp);
	if (!fc_port_enq_handler(outer_port, fcs_port_event, sp))
		goto error;
	return sp;

error:
	fcs_destroy(sp);
	return NULL;
}

static int fcs_drop(void *arg, struct fc_frame *fp)
{
	fc_frame_free(fp);
	return 0;
}

/*
 * Destroy and free the FCS state.
 */
void fcs_destroy(struct fcs_state *sp)
{
	struct fc_port *port;

	sp->fs_args.fca_disc_done = (void (*)(void *))fcs_nop;
	sp->fs_args.fca_remote_port_state_change =
	    (void (*)(void *, struct fc_remote_port *))fcs_nop;
	fcs_ev_add(sp, OFC_EV_HBA_DEL, NULL, 0);

	fc_port_set_egress(sp->fs_args.fca_port, fcs_drop, NULL);

	fc_port_deq_handler(sp->fs_args.fca_port, fcs_port_event, sp);
	port = sp->fs_inner_port;
	if (port) {
		sp->fs_inner_port = NULL;
		fc_port_close_ingress(port);
		fc_port_close_egress(port);
	}
	fc_port_close_ingress(sp->fs_args.fca_port);
	if (sp->fs_local_port) {
		fc_local_port_destroy(sp->fs_local_port);
		fc_local_port_release(sp->fs_local_port);
	}
	if (sp->fs_vf)
		fc_virt_fab_free(sp->fs_vf);
	fc_port_close_egress(sp->fs_args.fca_port);
	free(sp);
}

/*
 * XXX could be merely the ingress handler for the port?
 */
void fcs_recv(struct fcs_state *sp, struct fc_frame *fp)
{

	if (sp->fs_local_port) {
		fp->fr_in_port = sp->fs_inner_port;
		fc_local_port_recv(sp->fs_local_port, fp);
	} else {
		eprintf("fcs_local_port_set needed before receiving");
		fc_frame_free(fp);
	}
}

/*
 * Handler for new requests arriving.
 */
static void fcs_recv_req(void *sp_arg, struct fc_frame *fp)
{
	struct fcs_state *sp = sp_arg;
	struct fc_frame_header *fh;

	fh = fc_frame_header_get(fp);

	if (fh->fh_type == FC_TYPE_FCP && sp->fs_args.fca_fcp_recv) {
		(*sp->fs_args.fca_fcp_recv) (fp->fr_seq,
					     fp, sp->fs_args.fca_cb_arg);
	} else {
		fc_seq_hold(fp->fr_seq);
		fc_seq_exch_complete(fp->fr_seq);
		fc_frame_free(fp);
	}
}

/*
 * Set local port parameters.
 */
int fcs_local_port_set(struct fcs_state *sp, fc_wwn_t wwnn, fc_wwn_t wwpn)
{
	struct fc_local_port *lp;

	lp = fc_local_port_create(sp->fs_vf, sp->fs_inner_port, wwpn, wwnn,
				  sp->fs_args.fca_e_d_tov,
				  sp->fs_args.fca_plogi_retries);
	if (!lp)
		return -1;
	fc_local_port_set_prli_cb(lp, fcs_local_port_prli_accept, sp);
	fc_local_port_add_fc4_type(lp, FC_TYPE_FCP);
	fc_local_port_add_fc4_type(lp, FC_TYPE_CT);
	sp->fs_local_port = lp;
	fc_local_port_set_els_cb(lp, fcs_ev_els, sp);
	fcs_ev_add(sp, OFC_EV_HBA_ADD, NULL, 0);
	return 0;
}

/*
 * Start logins and discoveries.
 */
void fcs_start(struct fcs_state *sp)
{
	fc_local_port_logon(sp->fs_local_port, fcs_local_port_event, sp);
}

/*
 * Shutdown FCS, prepare for restart or fcs_destroy().
 */
void fcs_stop(struct fcs_state *sp)
{
	fc_local_port_logoff(sp->fs_local_port);
}

/*
 * Reset FCS.  Redo discovery.  Relogon to all sessions.
 * The caller may not have dropped its references to remote ports.
 * We logoff the local port and log back on when that's done,
 * which restarts discovery.
 */
void fcs_reset(struct fcs_state *sp)
{
	struct fc_local_port *lp;

	lp = sp->fs_local_port;
	sp->fs_disc_done = 0;
	fc_local_port_reset(lp);
}

static void fcs_local_port_event(int event, void *fcs_arg)
{
	struct fcs_state *sp = fcs_arg;
	struct fc_local_port *lp;
	int rc;

	dprintf("%d\n", event);

	lp = sp->fs_local_port;
	switch (event) {
	case FC_EV_READY:
		if (sp->fs_args.fca_service_params & FCP_SPPF_INIT_FCN) {
			rc = fc_disc_targ_start(lp, FC_TYPE_FCP,
						fcs_add_remote, sp);
			if (rc != 0)
				eprintf("target discovery start error %d", rc);
		} else {
			(*sp->fs_args.fca_disc_done) (sp->fs_args.fca_cb_arg);
		}
		fcs_ev_add(sp, OFC_EV_PT_ONLINE, NULL, 0);
		break;
	case FC_EV_DOWN:	/* local port will re-logon when it can */
		break;
	case FC_EV_CLOSED:	/* local port closed by driver */
		fcs_ev_add(sp, OFC_EV_PT_OFFLINE, NULL, 0);
		break;
	default:
		eprintf("unexpected event %d\n", event);
		break;
	}
}

/*
 * callback from local port when a PLOGI request is received
 */
static int fcs_local_port_prli_accept(struct fc_local_port *lp,
				      struct fc_remote_port *rp, void *fcs_arg)
{
	struct fcs_state *sp = fcs_arg;
	int reject = 0;

	rp->rp_local_fcp_parm = sp->fs_args.fca_service_params;
	if (fcs_debug)
		dprintf("PRLI callback. remote %6x local %6x\n",
		       rp->rp_fid, fc_local_port_get_fid(lp));
	if (sp->fs_args.fca_prli_accept)
		reject = (*sp->fs_args.fca_prli_accept) (sp->fs_args.fca_cb_arg,
							 rp);
	if (fcs_debug)
		dprintf("%s remote fid %6x\n",
		       reject ? "reject" : "accept", rp->rp_fid);
	return reject;
}

fc_fid_t fcs_get_fid(const struct fcs_state *sp)
{
	return fc_local_port_get_fid(sp->fs_local_port);
}

/*
 * Notification from discovery of a new remote port.
 * Create a session and wait for notification on the session state before
 * reporting the remote port as usable/found.
 * rp is NULL if discovery is complete.
 */
static void fcs_add_remote(void *fcs_arg, struct fc_remote_port *rp,
			   enum fc_event event)
{
	struct fcs_state *sp = fcs_arg;
	struct fc_local_port *lp;
	struct fc_sess *sess;

	dprintf("%d\n", event);

	lp = sp->fs_local_port;

	if (event == FC_EV_CLOSED) {
		if (fcs_debug)
			dprintf("removing remote fid %x wwpn %llx ref %d",
			       rp->rp_fid, rp->rp_port_wwn,
			       rp->rp_refcnt);
		fcs_ev_add(sp, OFC_EV_TARG_REMOVED,
			   &rp->rp_port_wwn, sizeof(rp->rp_port_wwn));
		(*sp->fs_args.fca_remote_port_state_change) (sp->fs_args.
							     fca_cb_arg, rp);
	} else if (rp) {
		fcs_ev_add(sp, OFC_EV_PT_NEW_TARG, NULL, 0);
		rp->rp_local_fcp_parm = sp->fs_args.fca_service_params;
		rp->rp_fcs_priv = sp;
		if (event == FC_EV_START) {
			if (fcs_debug)
				dprintf("new remote fid %x wwpn %llx",
				       rp->rp_fid, rp->rp_port_wwn);
			sess = rp->rp_sess;
			if (sess) {
				sp->fs_disc_done = 0;
				fc_sess_event_enq(sess, fcs_sess_event, rp);
				fc_sess_start(sess);
			}
		} else if (fcs_debug) {
			dprintf("old remote fid %x wwpn %llx", rp->rp_fid,
			       rp->rp_port_wwn);
		}
	} else {
		if (fcs_debug)
			dprintf("discovery complete");
		if (!sp->fs_disc_done)
			(*sp->fs_args.fca_disc_done) (sp->fs_args.fca_cb_arg);
		sp->fs_disc_done = 1;
	}
}

/*
 * Session event handler.
 * Note that the argument is the associated remote port for now.
 */
static void fcs_sess_event(int event, void *rp_arg)
{
	struct fc_remote_port *rp = rp_arg;
	struct fcs_state *sp;
	void *arg;

	sp = rp->rp_fcs_priv;
	arg = sp->fs_args.fca_cb_arg;

	switch (event) {
	case FC_EV_READY:
		rp->rp_sess_ready = 1;
		if (fcs_debug)
			dprintf("remote %6x ready", rp->rp_fid);
		(*sp->fs_args.fca_remote_port_state_change) (arg, rp);
		fcs_ev_add(sp, OFC_EV_TARG_ONLINE,
			   &rp->rp_port_wwn, sizeof(rp->rp_port_wwn));
		break;
	case FC_EV_RJT:	/* retries exhausted */
		if (fcs_debug)
			dprintf("remote %6x error", rp->rp_fid);
		break;
	case FC_EV_CLOSED:
		rp->rp_sess_ready = 0;
		if (fcs_debug)
			dprintf("remote %6x closed", rp->rp_fid);
		(*sp->fs_args.fca_remote_port_state_change) (arg, rp);
		fcs_ev_add(sp, OFC_EV_TARG_OFFLINE,
			   &rp->rp_port_wwn, sizeof(rp->rp_port_wwn));
		break;
	default:
		break;
	}
}

/*
 * Return a session that can be used for access to a remote port.
 * If there is no session, or it is not ready (PRLI is not complete),
 * NULL is returned.
 */
struct fc_sess *fcs_sess_get(struct fcs_state *sp, struct fc_remote_port *rp)
{
	struct fc_sess *sess = NULL;

	if (rp->rp_sess_ready)
		sess = rp->rp_sess;
	return sess;
}

static void fcs_port_event(int event, void *sp_arg)
{
	struct fcs_state *sp = sp_arg;

	switch (event) {
	case FC_EV_DOWN:
		fcs_ev_add(sp, OFC_EV_LINK_DOWN, NULL, 0);
		break;
	case FC_EV_READY:
		fcs_ev_add(sp, OFC_EV_LINK_UP, NULL, 0);
		break;
	}
	fc_port_send_event(sp->fs_inner_port, event);
}

struct fc_local_port *fcs_get_local_port(struct fcs_state *sp)
{
	return sp->fs_local_port;
}
