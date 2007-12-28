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
 * Virtual Fabric Support
 *
 * A virtual fabric has lookup tabless for the local_ports,
 * sessions, and remote_ports in the fabric.
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
#include "net_types.h"

#include "fc_encaps.h"

#include "fc_types.h"
#include "fc_remote_port.h"
#include "fc_local_port.h"
#include "fc_exch.h"
#include "fc_sess.h"
#include "fc_virt_fab.h"

#include "fc_virt_fab_impl.h"

struct fc_virt_fab *fc_virt_fab_alloc(u_int tag, enum fc_class class,
				      fc_xid_t min_xid, fc_xid_t max_xid)
{
	struct fc_virt_fab *vp;

	vp = zalloc(sizeof(*vp));
	if (!vp)
		return NULL;
	vp->vf_tag = tag;

	if (class != FC_CLASS_NONE) {

		vp->vf_exch_mgr = fc_exch_mgr_alloc(class, min_xid, max_xid);

		if (!vp->vf_exch_mgr)
			goto out_em;
	}
	if (fc_sess_table_create(vp))
		goto out_sp;
	if (fc_remote_port_table_create(vp))
		goto out_rp;
	if (fc_local_port_table_create(vp))
		goto out_lp;
	return vp;

out_lp:
	fc_remote_port_table_destroy(vp);
out_rp:
	fc_sess_table_destroy(vp);
out_sp:
	if (vp->vf_exch_mgr)
		fc_exch_mgr_free(vp->vf_exch_mgr);
out_em:
	free(vp);
	return NULL;
}

void fc_virt_fab_free(struct fc_virt_fab *vp)
{
	fc_sess_table_destroy(vp);
	fc_remote_port_table_destroy(vp);
	fc_local_port_table_destroy(vp);
	if (vp->vf_exch_mgr)
		fc_exch_mgr_free(vp->vf_exch_mgr);
	free(vp);
}
