#ifndef __TRANSPORT_H
#define __TRANSPORT_H

#include <sys/socket.h>

struct iscsi_connection;

struct iscsi_transport {
	const char *name;
	int rdma;

	int (*ep_init) (void);
	int (*ep_login_complete)(struct iscsi_connection *conn);
	size_t (*ep_read)(struct iscsi_connection *conn, void *buf,
			  size_t nbytes);
	size_t (*ep_write_begin)(struct iscsi_connection *conn, void *buf,
				 size_t nbytes);
	void (*ep_write_end)(struct iscsi_connection *conn);
	size_t (*ep_close)(struct iscsi_connection *conn);
	void (*ep_release)(struct iscsi_connection *conn);

	int (*ep_show)(struct iscsi_connection *conn, char *buf, int rest);
	void (*ep_event_modify)(struct iscsi_connection *conn, int events);
	void *(*alloc_data_buf)(struct iscsi_connection *conn, size_t sz);
	void (*free_data_buf)(struct iscsi_connection *conn, void *buf);
	int (*ep_getsockname)(struct iscsi_connection *conn,
			      struct sockaddr *sa, socklen_t *len);
	int (*ep_getpeername)(struct iscsi_connection *conn,
			      struct sockaddr *sa, socklen_t *len);
};

extern struct iscsi_transport iscsi_tcp;

#endif
