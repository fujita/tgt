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

#ifndef _LIBFC_REMOTE_PORT_H_
#define _LIBFC_REMOTE_PORT_H_

#include "sa_hash.h"

/*
 * Fibre Channel Remote Ports.
 * (was once called peer_port and port_info).
 */

/*
 * Fibre Channel information about remote N port.
 */
struct fc_remote_port {
	struct list_head rp_list;	/* list under fc_virt_fab */
	struct fc_virt_fab *rp_vf;	/* virtual fabric */
	fc_wwn_t	rp_port_wwn;	/* remote port world wide name */
	fc_wwn_t	rp_node_wwn;	/* remote node world wide name */
	fc_fid_t	rp_fid;		/* F_ID for remote_port if known */
	int	rp_refcnt;	/* reference count */
	u_int		rp_disc_ver;	/* discovery instance */
	u_int		rp_io_limit;	/* limit on outstanding I/Os */
	u_int		rp_io_count;	/* count of outstanding I/Os */
	u_int		rp_fcp_parm; 	/* remote FCP service parameters */
	u_int		rp_local_fcp_parm; /* local FCP service parameters */
	void		*rp_client_priv; /* HBA driver private data */
	void		*rp_fcs_priv;	/* FCS driver private data */
	struct sa_event_list *rp_events; /* event list */
	struct sa_hash_link rp_fid_hash_link;
	struct sa_hash_link rp_wwpn_hash_link;

	/*
	 * For now, there's just one session per remote port.
	 * Eventually, for multipathing, there will be more.
	 */
	u_char		rp_sess_ready;	/* session ready to be used */
	struct fc_sess	*rp_sess;	/* session */
	void		*dns_lookup;	/* private dns lookup */
	int		dns_lookup_count; /* number of attempted lookups */
};

/*
 * remote ports are created and looked up by WWPN.
 */
struct fc_remote_port *fc_remote_port_create(struct fc_virt_fab *, fc_wwn_t);
struct fc_remote_port *fc_remote_port_lookup(struct fc_virt_fab *,
					     fc_fid_t, fc_wwn_t wwpn);
struct fc_remote_port *fc_remote_port_lookup_create(struct fc_virt_fab *,
						    fc_fid_t,
						    fc_wwn_t wwpn,
						    fc_wwn_t wwnn);
void fc_remote_port_hold(struct fc_remote_port *);
void fc_remote_port_release(struct fc_remote_port *);
int fc_remote_port_table_create(struct fc_virt_fab *);
void fc_remote_port_table_destroy(struct fc_virt_fab *);
void fc_remote_port_target_enable(struct fc_remote_port *);

/*
 * Set remote port's FCID.  This is for well-known addresses.
 */
void fc_remote_port_set_fid(struct fc_remote_port *, fc_fid_t);
void fc_remote_port_set_name(struct fc_remote_port *,
			     fc_wwn_t wwpn, fc_wwn_t wwnn);

#endif /* _LIBFC_REMOTE_PORT_H_ */
