#ifndef __TRANSPORT_H
#define __TRANSPORT_H

struct iscsi_transport {
	const char *name;
	int rdma;

	int (*init) (void);
	size_t (*ep_read) (int ep, void *buf, size_t nbytes);
	size_t (*ep_write_begin) (int ep, void *buf, size_t nbytes);
	void (*ep_write_end)(int ep);
	size_t (*ep_close) (int ep);
};

extern struct iscsi_transport iscsi_tcp;

#endif
