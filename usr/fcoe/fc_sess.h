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

#ifndef _LIBFC_SESS_H_
#define _LIBFC_SESS_H_

/*
 * Fibre Channel Sessions.
 */

/*
 * Semi-opaque structures used as function arguments.
 */
struct fc_sess;			/* See fc_sess_impl.h */
struct fc_local_port;		/* See fc_local_port_impl.h */
struct fc_remote_port;
struct fc_virt_fab;
struct fc_exch;
struct fc_seq;
struct fc_frame;
enum fc_event;

struct fc_sess *fc_sess_create(struct fc_local_port *,
			       struct fc_remote_port *);
void fc_sess_set_did(struct fc_sess *, fc_fid_t);
struct sa_event *fc_sess_event_enq(struct fc_sess *,
				sa_event_handler_t, void *);
void fc_sess_event_deq(struct fc_sess *, sa_event_handler_t, void *);
void fc_sess_start(struct fc_sess *);
void fc_sess_stop(struct fc_sess *);
void fc_sess_reset(struct fc_sess *);
void fc_sess_reset_list(struct fc_virt_fab *, struct list_head *);
void fc_sess_hold(struct fc_sess *);
void fc_sess_release(struct fc_sess *);

struct fc_seq *fc_sess_seq_alloc(struct fc_sess *,
				 void (*recv)(struct fc_seq *,
					       struct fc_frame *, void *),
				 void (*errh)(enum fc_event, void *),
				 void *arg);

int fc_sess_send_req(struct fc_sess *, struct fc_frame *,
		     void (*recv)(struct fc_seq *, struct fc_frame *, void *),
		     void (*errh)(enum fc_event, void *),
		     void *arg);

fc_fid_t fc_sess_get_sid(struct fc_sess *);
fc_fid_t fc_sess_get_did(struct fc_sess *);
u_int fc_sess_get_max_payload(struct fc_sess *);
struct fc_virt_fab *fc_sess_get_virt_fab(struct fc_sess *);
struct fc_local_port *fc_sess_get_local_port(struct fc_sess *);
struct fc_remote_port *fc_sess_get_remote_port(struct fc_sess *);
u_int fc_sess_get_e_d_tov(struct fc_sess *);
u_int fc_sess_get_r_a_tov(struct fc_sess *);
int	fc_sess_is_ready(struct fc_sess *);

/*
 * Form 64-bit hash lookup key from FCIDs.
 */
static inline u_int64_t fc_sess_key(fc_fid_t local, fc_fid_t remote)
{
	return ((u_int64_t) local << 24) | remote;
}

int fc_sess_table_create(struct fc_virt_fab *);
void fc_sess_table_destroy(struct fc_virt_fab *);

/*
 * Lookup or create a new session.
 */
struct fc_sess *fc_sess_lookup_create(struct fc_local_port *,
				      fc_fid_t, fc_wwn_t);

/*
 * Generate debugging information about sessions.
 */
size_t fc_sess_disp(struct fc_sess *, char *buf, size_t len);
size_t fc_sess_disp_all(struct fc_virt_fab *, char *buf, size_t len);

#endif /* _LIBFC_SESS_H_ */
