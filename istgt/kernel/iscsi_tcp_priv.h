/*
 * makeshift to use iscsi_tcp.c like library
 */

extern struct iscsi_cls_conn *
iscsi_tcp_conn_create(struct iscsi_cls_session *cls_session, uint32_t conn_idx);
extern static void
iscsi_tcp_conn_destroy(struct iscsi_cls_conn *cls_conn);
extern int iscsi_tcp_conn_bind(struct iscsi_cls_session *cls_session,
			       struct iscsi_cls_conn *cls_conn, uint64_t transport_eph,
			       int is_leading);
extern void iscsi_tcp_terminate_conn(struct iscsi_conn *conn);

extern struct iscsi_cls_session *
iscsi_tcp_session_create(struct iscsi_transport *iscsit,
			 struct scsi_transport_template *scsit,
			 uint32_t initial_cmdsn, uint32_t *hostno);
extern void iscsi_tcp_session_destroy(struct iscsi_cls_session *cls_session);

extern inline int iscsi_hdr_extract(struct iscsi_tcp_conn *tcp_conn);
extern int iscsi_scsi_data_in(struct iscsi_conn *conn);
extern inline int iscsi_tcp_copy(struct iscsi_tcp_conn *tcp_conn);

extern int iscsi_tcp_hdr_recv_pre(struct iscsi_conn *conn);

extern int iscsi_tcp_init(void);
extern void iscsi_tcp_exit(void);
