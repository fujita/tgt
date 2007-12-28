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
 * Target Discovery
 * Actually, this discovers all FC-4 remote ports, including FCP initiators.
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

#include "fc_encaps.h"
#include "fc_fs.h"
#include "fc_els.h"
#include "fc_ils.h"
#include "fc_fc2.h"
#include "fc_gs.h"
#include "fc_ns.h"

#include "fc_types.h"
#include "fc_event.h"
#include "fc_local_port.h"
#include "fc_remote_port.h"
#include "fc_sess.h"
#include "fc_port.h"
#include "fc_exch.h"
#include "fc_disc_targ.h"
#include "fc_frame.h"

#include "fc_virt_fab_impl.h"
#include "fc_local_port_impl.h"
#include "fc_exch_impl.h"
#include "fc_sess_impl.h"

#define FCDT_RETRY_LIMIT    	3	/* max retries */

static int fcdt_disc_targ(struct fc_local_port *);
static void fcdt_gpn_ft_req(struct fc_local_port *);
static void fcdt_gpn_ft_resp(struct fc_seq *, struct fc_frame *, void *);
static int fcdt_new_target(struct fc_local_port *, struct fc_remote_port *,
			   fc_fid_t, fc_wwn_t);
static void fcdt_del_target(struct fc_local_port *, struct fc_remote_port *);
static void fcdt_done(struct fc_local_port *);
static void fcdt_error(enum fc_event, void *);
static void fcdt_timeout(void *);
static int fcdt_gpn_id_req(struct fc_local_port *, struct fc_remote_port *);
static void fcdt_gpn_id_resp(struct fc_seq *, struct fc_frame *, void *);
static void fcdt_gpn_id_error(enum fc_event, void *);

/*
 * Fibre Channel Target discovery.
 *
 * Returns non-zero if discovery cannot be started.
 *
 * Callback is called for each target remote port found in discovery.
 * When discovery is complete, the callback is called with a NULL remote port.
 * Discovery may be restarted after an RSCN is received, causing the
 * callback to be called after discovery complete is indicated.
 */
int fc_disc_targ_start(struct fc_local_port *lp,
		       u_int fc4_type,
		       void (*callback) (void *arg, struct fc_remote_port *,
					 enum fc_event), void *arg)
{
	(void)fc_disc_targ_register_callback(lp, fc4_type, callback, arg);
	return fcdt_disc_targ(lp);
}

/*
 * Register a callback for the discovery engine to return RSCNs and such
 */
int fc_disc_targ_register_callback(struct fc_local_port *lp,
				   u_int fc4_type,
				   void (*callback) (void *arg,
						     struct fc_remote_port *,
						     enum fc_event), void *arg)
{
	fc_local_port_lock(lp);
	lp->fl_disc_cb = callback;
	lp->fl_disc_cb_arg = arg;
	lp->fl_disc_type = fc4_type;
	sa_timer_init(&lp->fl_disc_timer, fcdt_timeout, lp);
	fc_local_port_unlock(lp);

	return (0);
}

/*
 * Refresh target discovery, perhaps due to an RSCN.
 * A configurable delay is introduced to collect any subsequent RSCNs.
 */
int fc_disc_targ_restart(struct fc_local_port *lp)
{
	fc_local_port_lock(lp);
	if (!lp->fl_disc_req && !lp->fl_disc_in_prog) {
		sa_timer_set(&lp->fl_disc_timer,
			     lp->fl_disc_holdoff * SA_TIMER_UNITS);
	}
	lp->fl_disc_req = 1;
	fc_local_port_unlock(lp);
	return 0;
}

/*
 * Perform target discovery.
 */
static int fcdt_disc_targ(struct fc_local_port *lp)
{
	struct fc_remote_port *rp;
	int error;

	fc_local_port_lock(lp);

	/*
	 * If not ready, or already running discovery, just set request flag.
	 */
	if (!fc_local_port_test_ready(lp) || lp->fl_disc_in_prog) {
		lp->fl_disc_req = 1;
		fc_local_port_unlock(lp);
		return 0;
	}
	lp->fl_disc_in_prog = 1;
	lp->fl_disc_req = 0;
	lp->fl_disc_ver++;
	lp->fl_disc_retries = 0;

	/*
	 * Handle point-to-point mode as a simple discovery
	 * of the remote port.
	 */
	rp = lp->fl_ptp_rp;
	if (rp) {
		fc_remote_port_hold(rp);
		fc_local_port_unlock(lp);
		error = fcdt_new_target(lp, rp, rp->rp_fid, rp->rp_port_wwn);
		fc_remote_port_release(rp);
		if (!error)
			fcdt_done(lp);
	} else {
		fc_local_port_unlock(lp);
		fcdt_gpn_ft_req(lp);	/* get ports by FC-4 type */
		error = 0;
	}
	return error;
}

/*
 * Restart discovery after a delay due to resource shortages.
 * If the error persists, the discovery will be abandoned.
 */
static void fcdt_retry(struct fc_local_port *lp)
{
	u_long delay = SA_TIMER_UNITS / 2;	/* 500 mS timeout */

	if (!lp->fl_disc_retries)
		delay /= 4;	/* timeout faster first time */
	if (lp->fl_disc_retries++ < FCDT_RETRY_LIMIT)
		sa_timer_set(&lp->fl_disc_timer, delay);
	else
		fcdt_done(lp);
}

/*
 * Handle new target found by discovery.
 * Create remote port and session if needed.
 * Ignore returns of our own FID & WWPN.
 *
 * If a non-NULL rp is passed in, it is held for the caller, but not for us.
 *
 * Events delivered are:
 *  FC_EV_START, on initial add.
 *  FC_EV_READY, when remote port is rediscovered.
 */
static int fcdt_new_target(struct fc_local_port *lp,
			   struct fc_remote_port *rp, fc_fid_t fid,
			   fc_wwn_t wwpn)
{
	struct fc_remote_port *new_rp = NULL;
	struct fc_sess *sess;
	enum fc_event event;
	int error = 0;

	if (rp && wwpn) {
		if (rp->rp_port_wwn == 0) {
			/*
			 * Set WWN and fall through to notify of create.
			 */
			fc_remote_port_set_name(rp, wwpn, rp->rp_node_wwn);
		} else if (rp->rp_port_wwn != wwpn) {
			/*
			 * This is a new port with the same FCID as
			 * a previously-discovered port.  Presumably the old
			 * port logged out and a new port logged in and was
			 * assigned the same FCID.  This should be rare.
			 * Delete the old one and fall thru to re-create.
			 */
			fcdt_del_target(lp, rp);
			rp = NULL;
		}
	}
	if ((wwpn || fid) && fid != lp->fl_fid && wwpn != lp->fl_port_wwn) {
		event = FC_EV_READY;
		if (!rp) {
			rp = fc_remote_port_lookup_create(lp->fl_vf, fid,
							  wwpn, 0);
			if (!rp)
				error = ENOMEM;
			new_rp = rp;
		}
		if (rp && rp->rp_disc_ver != lp->fl_disc_ver) {
			if (rp->rp_disc_ver == 0 || rp->rp_sess_ready == 0)
				event = FC_EV_START;
			sess = rp->rp_sess;
			if (!sess) {
				sess = fc_sess_lookup_create(lp, fid, wwpn);
				rp->rp_sess = sess;
			}
			if (sess) {
				rp->rp_disc_ver = lp->fl_disc_ver;
				(*lp->fl_disc_cb) (lp->fl_disc_cb_arg, rp,
						   event);
			}
		}
		if (new_rp)
			fc_remote_port_release(new_rp);
	}
	return error;
}

/*
 * Delete the remote port.
 */
static void fcdt_del_target(struct fc_local_port *lp, struct fc_remote_port *rp)
{
	struct fc_sess *sess;

	sess = rp->rp_sess;
	if (sess) {
		rp->rp_sess_ready = 0;
		rp->rp_sess = NULL;
		fc_sess_reset(sess);
		fc_sess_release(sess);	/* release hold from create */
	}
	rp->rp_disc_ver = 0;	/* mark it as "new" */
	(*lp->fl_disc_cb) (lp->fl_disc_cb_arg, rp, FC_EV_CLOSED);
}

/*
 * Done with discovery
 */
static void fcdt_done(struct fc_local_port *lp)
{
	struct fc_remote_port *rp;
	struct fc_remote_port *next;
	struct fc_remote_port *held;
	struct fc_virt_fab *vp;
	u_int disc_ver;

	/*
	 * Go through all remote_ports on the fabric which were not touched
	 * by this discovery, and disable them.  The affected remote port
	 * should be reported as not-reachable.
	 */
	vp = lp->fl_vf;
	fc_virt_fab_lock(vp);
	disc_ver = lp->fl_disc_ver;
	held = NULL;
	list_for_each_entry_safe(rp, next, &vp->vf_remote_ports, rp_list) {
		if (&next->rp_list != &vp->vf_remote_ports)
			fc_remote_port_hold(next);
		if (rp->rp_disc_ver != disc_ver && rp->rp_disc_ver) {
			if (!held)
				fc_remote_port_hold(rp);
			fc_virt_fab_unlock(vp);
			fcdt_del_target(lp, rp);
			fc_remote_port_release(rp);
			fc_virt_fab_lock(vp);
		} else if (held) {
			fc_virt_fab_unlock(vp);
			fc_remote_port_release(held);
			fc_virt_fab_lock(vp);
		}
		if (&next->rp_list != &vp->vf_remote_ports)
			held = next;
		else
			held = NULL;
	}
	fc_virt_fab_unlock(vp);
	(*lp->fl_disc_cb) (lp->fl_disc_cb_arg, NULL, FC_EV_NONE);
	lp->fl_disc_in_prog = 0;
	if (lp->fl_disc_req)
		fcdt_disc_targ(lp);
}

/*
 * Fill in request header.
 */
static void fcdt_fill_dns_hdr(struct fc_local_port *lp, struct fc_ct_hdr *ct,
			      u_int op, u_int req_size)
{
	memset(ct, 0, sizeof(*ct) + req_size);
	ct->ct_rev = FC_CT_REV;
	ct->ct_fs_type = FC_FST_DIR;
	ct->ct_fs_subtype = FC_NS_SUBTYPE;
	net16_put(&ct->ct_cmd, (u_int16_t) op);
}

static void fcdt_gpn_ft_req(struct fc_local_port *lp)
{
	struct fc_frame *fp;
	struct req {
		struct fc_ct_hdr ct;
		struct fc_ns_gid_ft gid;
	} *rp;
	int error;

	lp->fl_disc_buf_len = 0;
	lp->fl_disc_seq_cnt = 0;
	fp = fc_frame_alloc(lp->fl_port, sizeof(*rp));
	if (fp == NULL) {
		error = ENOMEM;
	} else {
		rp = fc_frame_payload_get(fp, sizeof(*rp));
		fcdt_fill_dns_hdr(lp, &rp->ct, FC_NS_GPN_FT, sizeof(rp->gid));
		rp->gid.fn_fc4_type = lp->fl_disc_type;

		fc_frame_setup(fp, FC_RCTL_DD_UNSOL_CTL, FC_TYPE_CT);
		error = fc_sess_send_req(lp->fl_dns_sess, fp, fcdt_gpn_ft_resp,
					 fcdt_error, lp);
	}
	if (error)
		fcdt_retry(lp);
}

/*
 * Handle error on dNS request.
 */
static void fcdt_error(enum fc_event event, void *lp_arg)
{
	struct fc_local_port *lp = lp_arg;

	switch (event) {
	case FC_EV_TIMEOUT:
		if (lp->fl_disc_retries++ < FCDT_RETRY_LIMIT) {
			fcdt_gpn_ft_req(lp);
		} else {
			dprintf("event %d - ending", event);
			fcdt_done(lp);
		}
		break;
	default:
		dprintf("event %d - ending", event);
		fcdt_done(lp);
		break;
	}
}

/*
 * Parse the list of port IDs and names resulting from a discovery request.
 */
static int fcdt_gpn_ft_parse(struct fc_local_port *lp, void *buf, size_t len)
{
	struct fc_gpn_ft_resp *np;
	fc_fid_t fid;
	fc_wwn_t wwpn;
	char *bp;
	size_t plen;
	size_t tlen;
	int error = 0;

	/*
	 * Handle partial name record left over from previous call.
	 */
	bp = buf;
	plen = len;
	np = (struct fc_gpn_ft_resp *)bp;
	tlen = lp->fl_disc_buf_len;
	if (tlen) {
		plen = sizeof(*np) - tlen;
		if (plen > len)
			plen = len;
		np = &lp->fl_disc_buf;
		memcpy((char *)np + tlen, bp, plen);

		/*
		 * Set bp so that the loop below will advance it to the
		 * first valid full name element.
		 */
		bp -= tlen;
		len += tlen;
		plen += tlen;
		lp->fl_disc_buf_len = (u_char) plen;
		if (plen == sizeof(*np))
			lp->fl_disc_buf_len = 0;
	}

	/*
	 * Handle full name records, including the one filled from above.
	 * Normally, np == bp and plen == len, but from the partial case above,
	 * bp, len describe the overall buffer, and np, plen describe the
	 * partial buffer, which if would usually be full now.
	 * After the first time through the loop, things return to "normal".
	 */
	while (plen >= sizeof(*np)) {
		fid = net24_get(&np->fp_fid);
		wwpn = net64_get(&np->fp_wwpn);
		error = fcdt_new_target(lp, NULL, fid, wwpn);
		if (error)
			break;
		if (np->fp_flags & FC_NS_FID_LAST) {
			fcdt_done(lp);
			len = 0;
			break;
		}
		len -= sizeof(*np);
		bp += sizeof(*np);
		np = (struct fc_gpn_ft_resp *)bp;
		plen = len;
	}

	/*
	 * Save any partial record at the end of the buffer for next time.
	 */
	if (error == 0 && len > 0 && len < sizeof(*np)) {
		if (np != &lp->fl_disc_buf)
			memcpy(&lp->fl_disc_buf, np, len);
		lp->fl_disc_buf_len = (u_char) len;
	} else {
		lp->fl_disc_buf_len = 0;
	}
	return error;
}

/*
 * Handle retry of memory allocation for remote ports.
 */
static void fcdt_timeout(void *lp_arg)
{
	struct fc_local_port *lp = lp_arg;

	if (lp->fl_disc_in_prog)
		fcdt_gpn_ft_req(lp);
	else
		fcdt_disc_targ(lp);
}

/*
 * Handle a response frame from Get Port Names (GPN_FT).
 * The response may be in multiple frames
 */
static void fcdt_gpn_ft_resp(struct fc_seq *sp, struct fc_frame *fp,
			     void *lp_arg)
{
	struct fc_local_port *lp = lp_arg;
	struct fc_ct_hdr *cp;
	struct fc_frame_header *fh;
	u_int seq_cnt;
	void *buf = NULL;
	u_int len;
	int error;

	fh = fc_frame_header_get(fp);
	len = fp->fr_len - sizeof(*fh);;
	seq_cnt = net16_get(&fh->fh_seq_cnt);
	if (fp->fr_sof == FC_SOF_I3 && seq_cnt == 0 &&
	    lp->fl_disc_seq_cnt == 0) {
		cp = fc_frame_payload_get(fp, sizeof(*cp));
		if (cp == NULL) {
			eprintf("GPN_FT response too short.  len %d",
			       fp->fr_len);
		} else if (net16_get(&cp->ct_cmd) == FC_FS_ACC) {

			/*
			 * Accepted.  Parse response.
			 */
			buf = cp + 1;
			len -= sizeof(*cp);
		} else if (net16_get(&cp->ct_cmd) == FC_FS_RJT) {
			eprintf("GPN_FT rejected reason %x exp %x "
			       "(check zoning)", cp->ct_reason, cp->ct_explan);
			fcdt_done(lp);
		} else {
			eprintf("GPN_FT unexpected response code %x\n",
			       net16_get(&cp->ct_cmd));
		}
	} else if (fp->fr_sof == FC_SOF_N3 && seq_cnt == lp->fl_disc_seq_cnt) {
		buf = fh + 1;
	} else {
		eprintf("GPN_FT unexpected frame - out of sequence? "
		       "seq_cnt %x expected %x sof %x eof %x",
		       seq_cnt, lp->fl_disc_seq_cnt, fp->fr_sof, fp->fr_eof);
	}
	if (buf) {
		error = fcdt_gpn_ft_parse(lp, buf, len);
		if (error)
			fcdt_retry(lp);
		else
			lp->fl_disc_seq_cnt++;
	}
	fc_frame_free(fp);
}

/*
 * Discover the directory information for a single target.
 * This could be from an RSCN that reported a change for the target.
 */
void fc_disc_targ_single(struct fc_local_port *lp, fc_fid_t fid)
{
	struct fc_remote_port *rp;

	if (fid == lp->fl_fid)
		return;
	rp = fc_remote_port_lookup_create(lp->fl_vf, fid, 0, 0);
	if (!rp)
		fc_disc_targ_restart(lp);	/* XXX do full discovery */
	else if (!lp->fl_disc_req)
		fcdt_gpn_id_req(lp, rp);
	else
		fc_remote_port_release(rp);
}

/*
 * Send Get Port Name by ID (GPN_ID) request.
 * The remote port is held by the caller for us.
 */
static int fcdt_gpn_id_req(struct fc_local_port *lp, struct fc_remote_port *rp)
{
	struct fc_frame *fp;
	struct req {
		struct fc_ct_hdr ct;
		struct fc_ns_fid fid;
	} *cp;
	int error;

	fp = fc_frame_alloc(lp->fl_port, sizeof(*cp));
	if (fp == NULL) {
		error = ENOMEM;
	} else {
		cp = fc_frame_payload_get(fp, sizeof(*cp));
		fcdt_fill_dns_hdr(lp, &cp->ct, FC_NS_GPN_ID, sizeof(cp->fid));
		net24_put(&cp->fid.fp_fid, rp->rp_fid);

		fc_frame_setup(fp, FC_RCTL_DD_UNSOL_CTL, FC_TYPE_CT);
		error = fc_sess_send_req(lp->fl_dns_sess, fp, fcdt_gpn_id_resp,
					 fcdt_gpn_id_error, rp);
	}
	return error;
}

/*
 * Handle a response frame from Get Port Name by ID (GPN_ID).
 */
static void fcdt_gpn_id_resp(struct fc_seq *sp, struct fc_frame *fp,
			     void *rp_arg)
{
	struct fc_remote_port *rp = rp_arg;
	struct fc_local_port *lp;
	struct resp {
		struct fc_ct_hdr ct;
		net64_t wwn;
	} *cp;
	fc_wwn_t wwpn;
	u_int cmd;

	lp = list_first_entry(&rp->rp_vf->vf_local_ports, struct fc_local_port, fl_list);

	cp = fc_frame_payload_get(fp, sizeof(cp->ct));
	if (cp == NULL) {
		eprintf("GPN_ID response too short.  len %d", fp->fr_len);
		return;
	}
	cmd = net16_get(&cp->ct.ct_cmd);
	switch (cmd) {
	case FC_FS_ACC:
		cp = fc_frame_payload_get(fp, sizeof(*cp));
		if (cp == NULL) {
			eprintf("GPN_ID response payload too short.  len %d",
			       fp->fr_len);
			break;
		}
		wwpn = net64_get(&cp->wwn);
		if (wwpn != lp->fl_port_wwn)
			fcdt_new_target(lp, rp, rp->rp_fid, wwpn);
		break;

	case FC_FS_RJT:
		if (cp->ct.ct_reason == FC_FS_RJT_UNABL &&
		    cp->ct.ct_explan == FC_FS_EXP_PID)
			fcdt_del_target(lp, rp);
		else
			fc_disc_targ_restart(lp);
		break;

	default:
		eprintf("GPN_ID unexpected CT response cmd %x\n", cmd);
		break;
	}
	fc_remote_port_release(rp);
	fc_frame_free(fp);
}

/*
 * Handle error from GPN_ID.
 */
static void fcdt_gpn_id_error(enum fc_event event, void *rp_arg)
{
	struct fc_remote_port *rp = rp_arg;
	struct fc_local_port *lp;

	switch (event) {
	case FC_EV_RJT:
	case FC_EV_TIMEOUT:
	case FC_EV_READY:
		lp = list_first_entry(&rp->rp_vf->vf_local_ports, struct fc_local_port, fl_list);
		fc_disc_targ_restart(lp);
		break;
	case FC_EV_CLOSED:
	default:
		break;
	}
	fc_remote_port_release(rp);
}
