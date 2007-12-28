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

#ifndef _LIBFC_FCS_STATE_H_
#define _LIBFC_FCS_STATE_H_

struct fcs_state;
struct fc_remote_port;
struct fc_local_port;

struct fcs_create_args {
	void		(*fca_remote_port_state_change)(void *arg,
					      struct fc_remote_port *);
	void		(*fca_disc_done)(void *arg);
	void		(*fca_fcp_recv)(struct fc_seq *, struct fc_frame *,
			      void *arg);
	int		(*fca_prli_accept)(void *arg, struct fc_remote_port *);
	void		(*fca_prlo_notify)(void *arg, struct fc_remote_port *);
	void		*fca_cb_arg;	/* arg for callbacks */
	struct fc_port *fca_port;	/* transport interface to FC fabric */
	u_int fca_service_params;	/* service parm flags from fc/fcp.h */
	fc_xid_t	fca_min_xid;	/* starting exchange ID */
	fc_xid_t	fca_max_xid;	/* maximum exchange ID */
	int		fca_e_d_tov;	/* error detection timeout (mS) */
	int		fca_plogi_retries; /* PLOGI retry limit */
};

void fcs_module_init(void);
void fcs_module_exit(void);

struct fcs_state *fcs_create(struct fcs_create_args *);
void fcs_destroy(struct fcs_state *);

void fcs_recv(struct fcs_state *, struct fc_frame *);
int fcs_local_port_set(struct fcs_state *, fc_wwn_t node, fc_wwn_t port);
int fcs_cmd_send(struct fcs_state *, struct fc_frame *,
			struct fc_frame *, u_int, u_int);
struct fc_local_port *fcs_get_local_port(struct fcs_state *);

/*
 * Get local port FC_ID.  Note this returns zero if the local port login
 * has not completed yet.
 */
fc_fid_t fcs_get_fid(const struct fcs_state *);

/*
 * Start discovery, setup sessions to remote ports.
 * (*fca_remote_port_state_change)() may be called once session is logged in.
 * (*fca_disc_done)() callback is invoked when this is complete.
 */
void fcs_start(struct fcs_state *);

/*
 * Logoff and prepare for fcs_destroy() or another fcs_start().
 */
void fcs_stop(struct fcs_state *);

/*
 * Do fabric logoff, relogon and redo discovery.
 */
void fcs_reset(struct fcs_state *);

/*
 * Get a session for access to a remote port.
 * If there is no session, or it is not ready (PRLI is not complete),
 * NULL is returned.
 */
struct fc_sess *fcs_sess_get(struct fcs_state *, struct fc_remote_port *);

int fcs_ev_get(uint32_t, void *buf, uint32_t, int);

#endif /* _LIBFC_FCS_STATE_H_ */
