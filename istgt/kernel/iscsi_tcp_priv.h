/*
 * makeshift to use iscsi_tcp.c like library
 */

extern struct iscsi_cls_conn *
iscsi_tcp_conn_create(struct iscsi_cls_session *cls_session, uint32_t conn_idx);
extern void iscsi_tcp_conn_destroy(struct iscsi_cls_conn *cls_conn);
extern int iscsi_tcp_conn_bind(struct iscsi_cls_session *cls_session,
			       struct iscsi_cls_conn *cls_conn, uint64_t transport_eph,
			       int is_leading);
extern void iscsi_tcp_terminate_conn(struct iscsi_conn *conn);

extern struct iscsi_cls_session *
iscsi_tcp_session_create(struct iscsi_transport *iscsit,
			 struct scsi_transport_template *scsit,
			 uint32_t initial_cmdsn, uint32_t *hostno);
extern void iscsi_tcp_session_destroy(struct iscsi_cls_session *cls_session);

extern int iscsi_hdr_extract(struct iscsi_tcp_conn *tcp_conn);
extern int iscsi_scsi_data_in(struct iscsi_conn *conn);

extern int iscsi_tcp_hdr_recv_pre(struct iscsi_conn *conn);
extern int iscsi_tcp_data_recv(read_descriptor_t *rd_desc, struct sk_buff *skb,
			       unsigned int offset, size_t len);

extern void
iscsi_buf_init_virt(struct iscsi_buf *ibuf, char *vbuf, int size);
extern void
iscsi_buf_init_sg(struct iscsi_buf *ibuf, struct scatterlist *sg);

extern int
iscsi_sendhdr(struct iscsi_conn *conn, struct iscsi_buf *buf, int datalen);
extern int
iscsi_sendpage(struct iscsi_conn *conn, struct iscsi_buf *buf,
	       int *count, int *sent);

extern int iscsi_tcp_init(void);
extern void iscsi_tcp_exit(void);
