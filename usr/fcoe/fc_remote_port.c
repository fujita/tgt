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
 * Remote Port support.
 *
 * A remote port structure contains information about an N port to which we
 * will create sessions.
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

#include "sa_event.h"
#include "sa_hash.h"

#include "fc_types.h"
#include "fc_remote_port.h"
#include "fc_virt_fab.h"
#include "fc_virt_fab_impl.h"

/*
 * Declare hash table type for lookup by FCID.
 */
#define	FC_REMOTE_PORT_HASH_SIZE	32	/* XXX smallish for now */

static int fc_remote_port_fid_match(sa_hash_key_t, void *);
static u_int32_t fc_remote_port_fid_hash(sa_hash_key_t);

static struct sa_hash_type fc_remote_port_hash_by_fid = {
	.st_link_offset = offsetof(struct fc_remote_port, rp_fid_hash_link),
	.st_match = fc_remote_port_fid_match,
	.st_hash = fc_remote_port_fid_hash,
};

#ifdef FC_REMOTE_PORT_BY_WWPN
/*
 * Declare hash table type for lookup by WWPN.
 */
static int fc_remote_port_wwpn_match(sa_hash_key_t, void *);
static u_int32_t fc_remote_port_wwpn_hash(sa_hash_key_t);

static struct sa_hash_type fc_remote_port_hash_by_wwpn = {
	.st_link_offset = offsetof(struct fc_remote_port, rp_wwpn_hash_link),
	.st_match = fc_remote_port_wwpn_match,
	.st_hash = fc_remote_port_wwpn_hash,
};
#endif /* FC_REMOTE_PORT_BY_WWPN */

int fc_remote_port_table_create(struct fc_virt_fab *vp)
{

	INIT_LIST_HEAD(&vp->vf_remote_ports);

	vp->vf_rport_by_fid = sa_hash_create(&fc_remote_port_hash_by_fid,
					     FC_REMOTE_PORT_HASH_SIZE);

	if (!vp->vf_rport_by_fid)
		return -1;

#ifdef FC_REMOTE_PORT_BY_WWPN
	vp->vf_rport_by_wwpn = sa_hash_create(&fc_remote_port_hash_by_wwpn,
					      FC_REMOTE_PORT_HASH_SIZE);

	if (!vp->vf_rport_by_wwpn) {
		sa_hash_destroy(vp->vf_rport_by_fid);
		return -1;
	}
#endif /* FC_REMOTE_PORT_BY_WWPN */
	return 0;
}

void fc_remote_port_table_destroy(struct fc_virt_fab *vp)
{
	INIT_LIST_HEAD(&vp->vf_remote_ports);
	if (vp->vf_rport_by_fid)
		sa_hash_destroy(vp->vf_rport_by_fid);
	vp->vf_rport_by_fid = NULL;

#ifdef FC_REMOTE_PORT_BY_WWPN
	if (vp->vf_rport_by_wwpn)
		sa_hash_destroy(vp->vf_rport_by_wwpn);
	vp->vf_rport_by_wwpn = NULL;
#endif /* FC_REMOTE_PORT_BY_WWPN */
}

struct fc_remote_port *fc_remote_port_create(struct fc_virt_fab *vp,
					     fc_wwn_t port_name)
{
	struct fc_remote_port *rp;

	rp = zalloc(sizeof(*rp));
	if (rp) {
		rp->rp_vf = vp;
		rp->rp_refcnt = 1;

		rp->rp_events = sa_event_list_alloc();

		if (!rp->rp_events) {
			free(rp);
			rp = NULL;
		} else {
			list_add_tail(&rp->rp_list, &vp->vf_remote_ports);
			fc_remote_port_set_name(rp, port_name, 0);
		}
	}
	return rp;
}

/*
 * Find remote port by FCID or by WWPN.
 * The first lookup is by FCID, if that is non-zero.  If that lookup fails,
 * a second lookup by WWPN (if that is non-zero) is performed.
 * Returns with the remote port held, or with NULL if the lookups fail.
 */
struct fc_remote_port *fc_remote_port_lookup(struct fc_virt_fab *vp,
					     fc_fid_t fid, fc_wwn_t wwpn)
{
	struct fc_remote_port *rp;

	rp = NULL;
	fc_virt_fab_lock(vp);
	if (fid)
		rp = sa_hash_lookup(vp->vf_rport_by_fid, &fid);
#ifdef FC_REMOTE_PORT_BY_WWPN
	if (!rp && wwpn)
		rp = sa_hash_lookup(vp->vf_rport_by_wwpn, &wwpn);
#endif /* FC_REMOTE_PORT_BY_WWPN */
	if (rp)
		fc_remote_port_hold(rp);
	fc_virt_fab_unlock(vp);
	return rp;
}

/*
 * Find remote port by FCID or by WWPN.  Create it if not found.
 * Returns with the remote port held.
 */
struct fc_remote_port *fc_remote_port_lookup_create(struct fc_virt_fab *vp,
						    fc_fid_t fid,
						    fc_wwn_t wwpn,
						    fc_wwn_t wwnn)
{
	struct fc_remote_port *rp;

	rp = NULL;
	fc_virt_fab_lock(vp);
	if (fid)
		rp = sa_hash_lookup(vp->vf_rport_by_fid, &fid);
#ifdef FC_REMOTE_PORT_BY_WWPN
	if (!rp && wwpn)
		rp = sa_hash_lookup(vp->vf_rport_by_wwpn, &wwpn);
#endif /* FC_REMOTE_PORT_BY_WWPN */
	if (!rp) {
		fc_virt_fab_unlock(vp);
		rp = fc_remote_port_create(vp, wwpn);
	} else {
		fc_remote_port_hold(rp);
		fc_virt_fab_unlock(vp);
	}
	if (rp) {
		if (fid && rp->rp_fid != fid)
			fc_remote_port_set_fid(rp, fid);
		if (wwpn && wwpn != rp->rp_port_wwn)
			fc_remote_port_set_name(rp, wwpn, wwnn);
	}
	return rp;
}

#ifdef FC_REMOTE_PORT_DEBUG
/*
 * Debug remote port print.
 */
static void fc_remote_port_print(void *rp_arg, void *msg_arg)
{
	struct fc_remote_port *rp = rp_arg;

	SA_LOG("%s rp %6x wwpn %16llx %p",
	       (char *)msg_arg, rp->rp_fid, rp->rp_port_wwn, rp);
}

/*
 * Debug print of remote ports from hash.
 */
static void fc_remote_port_list(struct fc_virt_fab *vp, char *msg,
				struct fc_remote_port *rp)
{
	SA_LOG("%s rp %6x %16llx %p", msg, rp->rp_fid, rp->rp_port_wwn, rp);
	sa_hash_iterate(vp->vf_rport_by_wwpn, fc_remote_port_print, "");
}
#endif /* FC_REMOTE_PORT_DEBUG */

/*
 * Set remote port's port and node names.
 */
void fc_remote_port_set_name(struct fc_remote_port *rp, fc_wwn_t wwpn,
			     fc_wwn_t wwnn)
{
#ifdef FC_REMOTE_PORT_BY_WWPN
	struct fc_remote_port *found_rp;
	struct fc_virt_fab *vp;
	fc_wwn_t old_name;

	vp = rp->rp_vf;
	fc_virt_fab_lock(vp);
	old_name = rp->rp_port_wwn;
	if (old_name) {
		found_rp = sa_hash_lookup_delete(vp->vf_rport_by_wwpn,
						 &old_name);
	}
#endif /* FC_REMOTE_PORT_BY_WWPN */
	rp->rp_node_wwn = wwnn;
	rp->rp_port_wwn = wwpn;
#ifdef FC_REMOTE_PORT_BY_WWPN
	if (wwpn != 0)
		sa_hash_insert(vp->vf_rport_by_wwpn, &wwpn, rp);
	fc_virt_fab_unlock(vp);
#endif /* FC_REMOTE_PORT_BY_WWPN */
}

/*
 * Set remote port's FCID.  This is mainly for well-known addresses.
 */
void fc_remote_port_set_fid(struct fc_remote_port *rp, fc_fid_t fid)
{
	struct fc_remote_port *found_rp;
	struct fc_virt_fab *vp;

	if (fid != rp->rp_fid) {
		vp = rp->rp_vf;
		fc_virt_fab_lock(vp);
		if (rp->rp_fid != 0) {
			found_rp = sa_hash_lookup_delete(vp->vf_rport_by_fid,
							 &rp->rp_fid);
		}
		rp->rp_fid = fid;
		if (fid)
			sa_hash_insert(vp->vf_rport_by_fid, &fid, rp);
		fc_virt_fab_unlock(vp);
	}
}

static void fc_remote_port_delete(struct fc_remote_port *rp)
{
	struct fc_remote_port *found;
	struct fc_virt_fab *vp;

	vp = rp->rp_vf;
	fc_virt_fab_lock(vp);
	if (rp->rp_fid != 0) {
		found = sa_hash_lookup_delete(rp->rp_vf->vf_rport_by_fid,
					      &rp->rp_fid);
	}
#ifdef FC_REMOTE_PORT_BY_WWPN
	if (rp->rp_port_wwn) {
		found = sa_hash_lookup_delete(rp->rp_vf->vf_rport_by_wwpn,
					      &rp->rp_port_wwn);
	}
#endif /* FC_REMOTE_PORT_BY_WWPN */
	list_del(&rp->rp_list);
	fc_virt_fab_unlock(vp);
	sa_event_list_free(rp->rp_events);
	free(rp);
}

void fc_remote_port_hold(struct fc_remote_port *rp)
{
	rp->rp_refcnt++;
}

void fc_remote_port_release(struct fc_remote_port *rp)
{
	if (!(--rp->rp_refcnt))
		fc_remote_port_delete(rp);
}

static int fc_remote_port_fid_match(sa_hash_key_t key, void *rp_arg)
{
	struct fc_remote_port *rp = rp_arg;

	return *(fc_fid_t *) key == rp->rp_fid;
}

static u_int32_t fc_remote_port_fid_hash(sa_hash_key_t key)
{
	return *(fc_fid_t *) key;
}

#ifdef FC_REMOTE_PORT_BY_WWPN
static int fc_remote_port_wwpn_match(sa_hash_key_t key, void *rp_arg)
{
	struct fc_remote_port *rp = rp_arg;

	return *(fc_wwn_t *) key == rp->rp_port_wwn;
}

static u_int32_t fc_remote_port_wwpn_hash(sa_hash_key_t key)
{
	fc_wwn_t wwn = *(fc_wwn_t *) key;

	return (u_int32_t) ((wwn >> 32) | wwn);
}
#endif /* FC_REMOTE_PORT_BY_WWPN */
