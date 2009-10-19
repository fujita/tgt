/*
 * iSCSI extensions for RDMA (iSER) data path
 *
 * Copyright (C) 2007 Dennis Dalessandro (dennis@osc.edu)
 * Copyright (C) 2007 Ananth Devulapalli (ananth@osc.edu)
 * Copyright (C) 2007 Pete Wyckoff (pw@osc.edu)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>
#include <netdb.h>
#include <sys/epoll.h>
#include <infiniband/verbs.h>
#include <rdma/rdma_cma.h>

#include "util.h"
#include "iscsid.h"

#if defined(HAVE_VALGRIND) && !defined(NDEBUG)
#include <valgrind/memcheck.h>
#else
#define VALGRIND_MAKE_MEM_DEFINED(addr, len)
#endif

/*
 * The IB-extended version from the kernel.  Stags and VAs are in
 * big-endian format.
 */
struct iser_hdr {
	uint8_t   flags;
	uint8_t   rsvd[3];
	uint32_t  write_stag; /* write rkey */
	uint64_t  write_va;
	uint32_t  read_stag;  /* read rkey */
	uint64_t  read_va;
} __attribute__((packed));

#define ISER_WSV	(0x08)
#define ISER_RSV	(0x04)
#define ISCSI_CTRL	(0x10)
#define ISER_HELLO	(0x20)
#define ISER_HELLORPLY	(0x30)

struct conn_info;

/*
 * Posted receives for control messages.  All must start with the conn
 * pointer, which will be followed up from a work request during a flush,
 * when it is not known what type to expect.
 */
struct recvlist {
	struct conn_info *conn;
	struct ibv_sge sge;
	void *buf;
	struct ibv_recv_wr wr;
	unsigned long bytes_recvd;
};

/*
 * Posted sends for control messages.
 */
struct sendlist {
	struct conn_info *conn;
	struct ibv_sge sge;
	void *buf;
	struct ibv_send_wr wr;
	struct list_head list;
};

/*
 * RDMA read and write operations.
 */
struct rdmalist {
	struct conn_info *conn;
	struct ibv_sge sge;
	struct ibv_send_wr wr;
	struct list_head list;
	struct iscsi_task *task;  /* to get iser_task for remote stag and va */
};

/*
 * Each SCSI command may have its own RDMA parameters.  These appear on
 * the connection then later are assigned to the particular task to be
 * used when the target responds.
 */
struct iser_task {
	/* read and write from the initiator's point of view */
	uint32_t rem_read_stag, rem_write_stag;
	uint64_t rem_read_va, rem_write_va;
	struct iscsi_task task;
};

struct iser_device;

/*
 * Parallels iscsi_connection.  Adds more fields for iser.
 */
struct conn_info {
	struct iscsi_connection iscsi_conn;
	struct ibv_qp *qp_hndl;
	struct rdma_cm_id *cma_id;
	struct iser_device *dev;
	struct sockaddr_storage peer_addr;  /* initiator address */
	struct sockaddr_storage self_addr;  /* target address */
	unsigned int ssize, rsize, max_outst_pdu;
	unsigned int readb, writeb;

	/* read and write from the initiator's point of view */
	uint32_t rem_read_stag, rem_write_stag;
	uint64_t rem_read_va, rem_write_va;

	enum {
	    LOGIN_PHASE_START,      /* keep 1 send spot and 1 recv posted */
	    LOGIN_PHASE_LAST_SEND,  /* need 1 more send before ff */
	    LOGIN_PHASE_FF,         /* full feature */
	} login_phase;

	void *srbuf;    /* registered space for non-rdma send and recv */
	void *listbuf;  /* space for the send, recv, rdma list elements */
	struct ibv_mr *srmr;   /* mr for registered srbuf */

	/* lists of free send, rdma slots */
	struct list_head sendl, rdmal;

	/* no recvl: just always immediately repost */
	/* but count so we can drain CQ on close */
	int recvl_posted;

	struct event_data tx_sched;

	/* login phase resources, freed at full-feature */
	void *srbuf_login;
	void *listbuf_login;
	struct ibv_mr *srmr_login;
	struct list_head sendl_login, recvl_login;

	/* points to the current recvlist, sendlist items for each conn */
	struct recvlist *rcv_comm_event;
	struct sendlist *send_comm_event;

	/* to chain this connection onto the list of those ready to tx */
	struct list_head conn_tx_ready;

	/* list of all iser conns */
	struct list_head iser_conn_list;

	/* to consume posted receives after disconnect */
	int draining;

	/* when free has been called, waits until all posted msgs complete */
	int freed;
};

/*
 * Pre-registered memory.  Buffers are allocated by iscsi from us, handed
 * to device to fill, then iser can send them directly without registration.
 * Also for write path.
 */
struct mempool {
	struct list_head list;
	void *buf;
};

/*
 * Shared variables for a particular device.  The conn[] array will
 * have to be broken out when multiple device support is added, maybe with
 * a pointer into this "device" struct.
 */
struct iser_device {
	struct list_head list;
	struct ibv_context *ibv_hndl;
	struct ibv_pd *pd;
	struct ibv_cq *cq;
	struct ibv_comp_channel *cq_channel;

	/* mempool registered buffer, list area, handle */
	void *mempool_regbuf;
	void *mempool_listbuf;
	struct ibv_mr *mempool_mr;

	struct event_data poll_sched;

	/* free and allocated mempool entries */
	struct list_head mempool_free, mempool_alloc;
};

static struct iscsi_transport iscsi_iser;

/* global, across all devices */
static struct rdma_event_channel *rdma_evt_channel;
static struct rdma_cm_id *cma_listen_id;
static struct list_head conn_tx_ready;  /* conns with tasks ready to tx */

/* accepted at RDMA layer, but not yet established */
static struct list_head temp_conn;

/* all devices */
static struct list_head iser_dev_list;

/* all iser connections */
static struct list_head iser_conn_list;

/* if any task needs an rdma read or write slot to proceed */
static int waiting_rdma_slot;

#define uint64_from_ptr(p) (uint64_t)(uintptr_t)(p)
#define ptr_from_int64(p) (void *)(unsigned long)(p)

#define ISCSI_LISTEN_PORT 3260

/*
 * Crazy hard-coded linux iser settings need 128 * 8 slots + slop, plus
 * room for our rdmas and send requests.
 */
#define MAX_WQE 1800

/*
 * Number of outstanding RDMAs per command; should instead wait for previous
 * RDMAs to complete before starting new ones.
 *
 * The RDMA size is completely up to the target.  Parameters IRDSL and TRDSL
 * only apply to control-type PDUs.  We allocate only so many rdma slots
 * per connection, but many tasks might be in progress on the connection.
 * Internal flow control stops tasks when there are no slots.
 *
 * RDMA size tradeoffs (MaxBurstLength):
 *    big RDMA operations are more efficient
 *    small RDMA operations better for fairness with many clients
 *    small RDMA operations allow better pipelining
 *    eventually target devices may not want to have to malloc and return
 *        entire buffer to transport in one go
 */
#define RDMA_PER_CONN 20

#define MAX_POLL_WC 8

/*
 * Number of allocatable data buffers, each of this size.  Do at least 128
 * for linux iser.  The mempool size is rounded up at initialization time
 * to the hardware page size so that allocations for direct IO devices are
 * aligned.
 */
static int mempool_num = 192;
static size_t mempool_size = 512 * 1024;

static inline struct iser_task *ISER_TASK(struct iscsi_task *t)
{
	return container_of(t, struct iser_task, task);
}

static inline struct conn_info *RDMA_CONN(struct iscsi_connection *conn)
{
	return container_of(conn, struct conn_info, iscsi_conn);
}

static void iser_cqe_handler(int fd __attribute__((unused)),
			     int events __attribute__((unused)),
			     void *data);
static void iser_rdma_read_completion(struct rdmalist *rdma);
static void iscsi_rdma_release(struct iscsi_connection *conn);
static int iscsi_rdma_show(struct iscsi_connection *conn, char *buf,
			   int rest);
static void iscsi_rdma_event_modify(struct iscsi_connection *conn, int events);
static void iser_sched_poll_cq(struct event_data *tev);
static void iser_sched_consume_cq(struct event_data *tev);
static void iser_sched_tx(struct event_data *evt);

/*
 * Called when ready for full feature, builds resources.
 */
static int iser_init_comm(struct conn_info *conn)
{
	unsigned int i;
	int ret = -1;
	unsigned long size;
	uint8_t *srbuf, *listbuf;
	struct sendlist *sendl;
	struct recvlist *recvl;
	struct rdmalist *rdmal;
	struct ibv_recv_wr *bad_wr;
	int rdma_per_conn = RDMA_PER_CONN;

	dprintf("sizing %u/%u outst %u\n", conn->ssize, conn->rsize,
		conn->max_outst_pdu);

	size = (conn->rsize + conn->ssize) * conn->max_outst_pdu;
	conn->srbuf = malloc(size);
	if (!conn->srbuf) {
		eprintf("malloc srbuf %lu\n", size);
		goto out;
	}

	conn->srmr = ibv_reg_mr(conn->dev->pd, conn->srbuf, size,
				IBV_ACCESS_LOCAL_WRITE);
	if (!conn->srmr) {
		eprintf("register srbuf\n");
		goto out;
	}

	INIT_LIST_HEAD(&conn->sendl);
	INIT_LIST_HEAD(&conn->rdmal);

	size = conn->max_outst_pdu * sizeof(struct sendlist) +
	       conn->max_outst_pdu * sizeof(struct recvlist) +
	       conn->max_outst_pdu * rdma_per_conn * sizeof(struct rdmalist);
	conn->listbuf = malloc(size);
	if (!conn->listbuf) {
		eprintf("malloc listbuf %lu\n", size);
		goto out;
	}
	memset(conn->listbuf, 0, size);

	srbuf = conn->srbuf;
	listbuf = conn->listbuf;
	for (i = 0; i < conn->max_outst_pdu; i++) {
		sendl = (void *) listbuf;
		listbuf += sizeof(*sendl);
		sendl->buf = srbuf;
		srbuf += conn->ssize;
		sendl->conn = conn;

		sendl->sge.addr = uint64_from_ptr(sendl->buf);
		sendl->sge.length = conn->ssize;
		sendl->sge.lkey = conn->srmr->lkey;

		sendl->wr.wr_id = uint64_from_ptr(sendl);
		sendl->wr.sg_list = &sendl->sge;
		sendl->wr.num_sge = 1;
		sendl->wr.opcode = IBV_WR_SEND;
		sendl->wr.send_flags = IBV_SEND_SIGNALED;
		list_add_tail(&sendl->list, &conn->sendl);
	}

	for (i = 0; i < conn->max_outst_pdu; i++) {
		recvl = (void *) listbuf;
		listbuf += sizeof(*recvl);
		recvl->buf = srbuf;
		srbuf += conn->rsize;
		recvl->conn = conn;

		recvl->sge.addr = uint64_from_ptr(recvl->buf);
		recvl->sge.length = conn->rsize;
		recvl->sge.lkey = conn->srmr->lkey;

		recvl->wr.wr_id = uint64_from_ptr(recvl);
		recvl->wr.sg_list = &recvl->sge;
		recvl->wr.num_sge = 1;

		ret = ibv_post_recv(conn->qp_hndl, &recvl->wr, &bad_wr);
		if (ret) {
			eprintf("ibv_post_recv (%d/%d): %m\n", i,
				conn->max_outst_pdu);
			exit(1);
		}
		++conn->recvl_posted;
	}

	for (i = 0; i < conn->max_outst_pdu * rdma_per_conn; i++) {
		rdmal = (void *) listbuf;
		listbuf += sizeof(*rdmal);
		rdmal->conn = conn;
		rdmal->sge.lkey = conn->dev->mempool_mr->lkey;

		rdmal->wr.wr_id = uint64_from_ptr(rdmal);
		rdmal->wr.sg_list = &rdmal->sge;
		rdmal->wr.num_sge = 1;
		rdmal->wr.send_flags = IBV_SEND_SIGNALED;
		list_add_tail(&rdmal->list, &conn->rdmal);
	}

	ret = 0;

out:
	return ret;
}

/*
 * Called at accept time, builds resources just for login phase.
 */
static int iser_init_comm_login(struct conn_info *conn)
{
	unsigned int i;
	int ret = -1;
	unsigned long size;
	uint8_t *srbuf, *listbuf;
	struct sendlist *sendl;
	struct recvlist *recvl;
	struct ibv_recv_wr *bad_wr;

	dprintf("sizing %u/%u outst %u\n", conn->ssize, conn->rsize,
		conn->max_outst_pdu);

	size = (conn->rsize + conn->ssize) * conn->max_outst_pdu;
	conn->srbuf_login = malloc(size);
	if (!conn->srbuf_login) {
		eprintf("malloc srbuf %lu\n", size);
		goto out;
	}

	conn->srmr_login = ibv_reg_mr(conn->dev->pd, conn->srbuf_login, size,
				      IBV_ACCESS_LOCAL_WRITE);
	if (!conn->srmr_login) {
		eprintf("ibv_reg_mr srbuf failed\n");
		goto out;
	}

	INIT_LIST_HEAD(&conn->sendl_login);
	INIT_LIST_HEAD(&conn->recvl_login);

	size = conn->max_outst_pdu * sizeof(struct sendlist) +
	       conn->max_outst_pdu * sizeof(struct recvlist);
	conn->listbuf_login = malloc(size);
	if (!conn->listbuf_login) {
		eprintf("malloc listbuf %lu\n", size);
		goto out;
	}
	memset(conn->listbuf_login, 0, size);

	srbuf = conn->srbuf_login;
	listbuf = conn->listbuf_login;
	for (i = 0; i < conn->max_outst_pdu; i++) {
		sendl = (void *) listbuf;
		listbuf += sizeof(*sendl);
		sendl->buf = srbuf;
		srbuf += conn->ssize;
		sendl->conn = conn;

		sendl->sge.addr = uint64_from_ptr(sendl->buf);
		sendl->sge.length = conn->ssize;
		sendl->sge.lkey = conn->srmr_login->lkey;

		sendl->wr.wr_id = uint64_from_ptr(sendl);
		sendl->wr.sg_list = &sendl->sge;
		sendl->wr.num_sge = 1;
		sendl->wr.opcode = IBV_WR_SEND;
		sendl->wr.send_flags = IBV_SEND_SIGNALED;
		list_add_tail(&sendl->list, &conn->sendl_login);
	}

	for (i = 0; i < conn->max_outst_pdu; i++) {
		recvl = (void *) listbuf;
		listbuf += sizeof(*recvl);
		recvl->buf = srbuf;
		srbuf += conn->rsize;
		recvl->conn = conn;

		recvl->sge.addr = uint64_from_ptr(recvl->buf);
		recvl->sge.length = conn->rsize;
		recvl->sge.lkey = conn->srmr_login->lkey;

		recvl->wr.wr_id = uint64_from_ptr(recvl);
		recvl->wr.sg_list = &recvl->sge;
		recvl->wr.num_sge = 1;
		recvl->wr.next = NULL;

		ret = ibv_post_recv(conn->qp_hndl, &recvl->wr, &bad_wr);
		if (ret) {
			eprintf("ibv_post_recv: %m\n");
			goto out;
		}
	}

	ret = 0;

out:
	return ret;
}

/*
 * On connection shutdown.
 */
static void iser_free_comm(struct conn_info *ci)
{
	int ret;

	dprintf("freeing conn %p\n", ci);

	/* release mr and free the lists */
	dprintf("dereg mr %p\n", ci->srmr);
	ret = ibv_dereg_mr(ci->srmr);
	if (ret)
		eprintf("ibv_dereg_mr\n");
	free(ci->srbuf);
	free(ci->listbuf);
}

/*
 * When ready for full-feature mode, free login-phase resources.
 */
static void iser_free_comm_login(struct conn_info *ci)
{
	int ret;

	if (ci->srbuf_login == NULL)
		return;

	dprintf("freeing, login phase %d\n", ci->login_phase);

	/* release mr and free the lists */
	ret = ibv_dereg_mr(ci->srmr_login);
	if (ret)
		eprintf("ibv_dereg_mr\n");
	free(ci->srbuf_login);
	free(ci->listbuf_login);
	ci->srbuf_login = NULL;  /* remember freed */
}

/*
 * One pool of registered memory per device (per PD that is).
 */
static int iser_init_mempool(struct iser_device *dev)
{
	struct mempool *mp;
	uint8_t *regbuf, *listbuf;
	int i;

	mempool_size = roundup(mempool_size, pagesize);
	regbuf = valloc(mempool_num * mempool_size);
	if (!regbuf) {
		eprintf("malloc regbuf %zu\n", mempool_num * mempool_size);
		return -ENOMEM;
	}

	listbuf = malloc(mempool_num * sizeof(*mp));
	if (!listbuf) {
		eprintf("malloc listbuf %zu\n", mempool_num * sizeof(*mp));
		free(regbuf);
		return -ENOMEM;
	}

	dev->mempool_mr = ibv_reg_mr(dev->pd, regbuf,
				     mempool_num * mempool_size,
				     IBV_ACCESS_LOCAL_WRITE);
	if (!dev->mempool_mr) {
		eprintf("register regbuf\n");
		free(regbuf);
		free(listbuf);
		return -1;
	}

	dev->mempool_regbuf = regbuf;
	dev->mempool_listbuf = listbuf;
	INIT_LIST_HEAD(&dev->mempool_free);
	INIT_LIST_HEAD(&dev->mempool_alloc);

	for (i = 0; i < mempool_num; i++) {
		mp = (void *) listbuf;
		listbuf += sizeof(*mp);
		mp->buf = regbuf;
		regbuf += mempool_size;
		list_add_tail(&mp->list, &dev->mempool_free);
	}

	return 0;
}

/*
 * First time a new connection is received on an RDMA device, record
 * it and build a PD and static memory.
 */
static int iser_device_init(struct iser_device *dev)
{
	struct ibv_device_attr device_attr;
	int cqe_num;
	int ret = -1;

	dprintf("dev %p\n", dev);
	dev->pd = ibv_alloc_pd(dev->ibv_hndl);
	if (dev->pd == NULL) {
		eprintf("ibv_alloc_pd failed\n");
		goto out;
	}

	ret = iser_init_mempool(dev);
	if (ret) {
		eprintf("iser_init_mempool failed\n");
		goto out;
	}

	ret = ibv_query_device(dev->ibv_hndl, &device_attr);
	if (ret < 0) {
		eprintf("ibv_query_device: %m\n");
		goto out;
	}
	cqe_num = device_attr.max_cqe;
	dprintf("max %d CQEs\n", cqe_num);

	ret = -1;
	dev->cq_channel = ibv_create_comp_channel(dev->ibv_hndl);
	if (dev->cq_channel == NULL) {
		eprintf("ibv_create_comp_channel failed: %m\n");
		goto out;
	}

	dev->cq = ibv_create_cq(dev->ibv_hndl, cqe_num, NULL,
				dev->cq_channel, 0);
	if (dev->cq == NULL) {
		eprintf("ibv_create_cq failed: %m\n");
		goto out;
	}

	tgt_init_sched_event(&dev->poll_sched, iser_sched_poll_cq, dev);

	ret = ibv_req_notify_cq(dev->cq, 0);
	if (ret) {
		eprintf("ibv_req_notify failed: %s\n", strerror(ret));
		goto out;
	}

	ret = tgt_event_add(dev->cq_channel->fd, EPOLLIN, iser_cqe_handler,
			    dev);
	if (ret) {
		eprintf("tgt_event_add failed: %m\n");
		goto out;

	}

	list_add(&dev->list, &iser_dev_list);

out:
	return ret;
}

static void iser_accept_connection(struct rdma_cm_event *event)
{
	int ret, found;
	struct ibv_qp_init_attr qp_init_attr;
	struct iscsi_connection *conn;
	struct conn_info *ci;
	struct iser_device *dev;
	unsigned int hdrsz;
	struct rdma_conn_param conn_param = {
		.responder_resources = 1,
		.initiator_depth = 1,
		.retry_count = 5,
	};

	dprintf("entry\n");

	/* find device */
	found = 0;
	list_for_each_entry(dev, &iser_dev_list, list) {
		if (dev->ibv_hndl == event->id->verbs) {
			found = 1;
			break;
		}
	}
	if (!found) {
		dev = malloc(sizeof(*dev));
		if (dev == NULL) {
			eprintf("unable to allocate dev\n");
			goto reject;
		}
		dev->ibv_hndl = event->id->verbs;
		ret = iser_device_init(dev);
		if (ret) {
			free(dev);
			goto reject;
		}
	}

	/* build a new connection structure */
	ci = zalloc(sizeof(*ci));
	if (!ci) {
		eprintf("unable to allocate conn\n");
		goto reject;
	}
	conn = &ci->iscsi_conn;

	ret = conn_init(conn);
	if (ret) {
		free(ci);
		goto reject;
	}

	conn->tp = &iscsi_iser;
	conn_read_pdu(conn);
	ci->cma_id = event->id;
	ci->dev = dev;
	ci->login_phase = LOGIN_PHASE_START;
	INIT_LIST_HEAD(&ci->conn_tx_ready);
	list_add(&ci->iser_conn_list, &temp_conn);

	tgt_init_sched_event(&ci->tx_sched, iser_sched_tx, ci);

	/* initiator sits at dst, we are src */
	memcpy(&ci->peer_addr, &event->id->route.addr.dst_addr,
	       sizeof(ci->peer_addr));
	memcpy(&ci->self_addr, &event->id->route.addr.src_addr,
	       sizeof(ci->self_addr));
#ifndef NDEBUG
	{
		char str[256];

		iscsi_rdma_show(conn, str, sizeof(str));
		str[sizeof(str)-1] = 0;
		dprintf("new conn %p from %s\n", ci, str);
	}
#endif

	/* create qp next */
	memset(&qp_init_attr, 0, sizeof(qp_init_attr));
	/* wire both send and recv to the same CQ */
	qp_init_attr.send_cq =  dev->cq;
	qp_init_attr.recv_cq  = dev->cq;
	qp_init_attr.cap.max_send_wr = MAX_WQE;
	qp_init_attr.cap.max_recv_wr = MAX_WQE;
	qp_init_attr.cap.max_send_sge = 1;  /* scatter/gather entries */
	qp_init_attr.cap.max_recv_sge = 1;
	qp_init_attr.qp_type = IBV_QPT_RC;
	/* only generate completion queue entries if requested */
	qp_init_attr.sq_sig_all = 0;

	ret = rdma_create_qp(ci->cma_id, dev->pd, &qp_init_attr);
	if (ret) {
		eprintf("create qp failed\n");
		goto free_conn;
	}
	ci->qp_hndl = ci->cma_id->qp;
	VALGRIND_MAKE_MEM_DEFINED(ci->qp_hndl, sizeof(*ci->qp_hndl));

	ci->rcv_comm_event = NULL;
	ci->send_comm_event = NULL;
	ci->readb = 0;
	ci->writeb = 0;

	/*
	 * Post buffers for the login phase, only.
	 */
	hdrsz = sizeof(struct iser_hdr) +
		sizeof(struct iscsi_hdr) +
		sizeof(struct iscsi_ecdb_ahdr) +
		sizeof(struct iscsi_rlength_ahdr);
	ci->ssize = hdrsz + 8192;
	ci->rsize = hdrsz + 8192;
	ci->max_outst_pdu = 1;
	ret = iser_init_comm_login(ci);
	if (ret) {
		iser_free_comm_login(ci);
		goto free_conn;
	}

	/* now we can actually accept the connection */
	ret = rdma_accept(ci->cma_id, &conn_param);
	if (ret) {
		eprintf("rdma_accept failed\n");
		iser_free_comm_login(ci);
		goto free_conn;
	}

	return;

free_conn:
	conn_exit(conn);
	free(ci);
reject:
	ret = rdma_reject(event->id, NULL, 0);
	if (ret)
		eprintf("rdma_reject failed: %s\n", strerror(-ret));
}

/*
 * Finish putting the connection together, now that the other side
 * has ACKed our acceptance.  Moves it from the temp_conn to the
 * iser_conn_list.
 *
 * Release the temporary conn_info and glue it into iser_conn_list.
 */
static void iser_conn_established(struct rdma_cm_event *event)
{
	int found = 0;
	struct conn_info *ci;

	/* find it in connection list */
	list_for_each_entry(ci, &temp_conn, iser_conn_list) {
		if (ci->cma_id == event->id) {
			found = 1;
			break;
		}
	}
	if (!found) {
		eprintf("cma id %p not found\n", event->id);
		return;
	}
	dprintf("established conn %p\n", ci);
	list_del(&ci->iser_conn_list);
	list_add(&ci->iser_conn_list, &iser_conn_list);
}

static void iser_disconnect(struct rdma_cm_event *ev)
{
	struct conn_info *ci;

	/*
	 * If not found, initiator disconnected first, so tell iscsi about
	 * it; else iscsi already did the conn_close.
	 */
	dprintf("initiator disconn, QP %d\n", ev->id->qp->qp_num);
	list_for_each_entry(ci, &iser_conn_list, iser_conn_list) {
		if (ci->qp_hndl->qp_num == ev->id->qp->qp_num) {
			struct iscsi_connection *conn = &ci->iscsi_conn;
			conn->state = STATE_CLOSE;
			conn_close(conn);
			break;
		}
	}
}

/*
 * Handle RDMA connection events.
 */
static void iser_handle_rdmacm(int fd __attribute__((unused)),
			       int events __attribute__((unused)),
			       void *data __attribute__((unused)))
{
	int ret;
	struct rdma_cm_event *event;
	struct rdma_cm_id *destroy_cm_id = NULL;

	dprintf("entry\n");
	ret = rdma_get_cm_event(rdma_evt_channel, &event);
	if (ret) {
		eprintf("rdma_get_cm_event failed\n");
		return;
	}

	VALGRIND_MAKE_MEM_DEFINED(event, sizeof(*event));
	switch (event->event) {
	case RDMA_CM_EVENT_CONNECT_REQUEST:
		iser_accept_connection(event);
		break;
	case RDMA_CM_EVENT_ESTABLISHED:
		iser_conn_established(event);
		break;
	case RDMA_CM_EVENT_DISCONNECTED:
		iser_disconnect(event);
		destroy_cm_id = event->id;
		break;
	default:
		eprintf("unknown event %d\n", event->event);
		break;
	}

	ret = rdma_ack_cm_event(event);
	if (ret) {
		eprintf("ack cm event failed\n");
		return;
	}

	if (destroy_cm_id) {
		ret = rdma_destroy_id(destroy_cm_id);
		if (ret)
			eprintf("rdma_destroy_id failed\n");
	}
}

/*
 * Deal with just one work completion.
 */
static void handle_wc(struct ibv_wc *wc)
{
	int ret;
	struct recvlist *recvl;
	struct sendlist *sendl;
	struct rdmalist *rdmal;
	struct conn_info *ci;
	struct iscsi_connection *conn;
	struct ibv_recv_wr *bad_wr;

	switch (wc->opcode) {
	case IBV_WC_SEND:
		dprintf("outgoing rsp complete\n");
		sendl = ptr_from_int64(wc->wr_id);
		ci = sendl->conn;
		if (ci->login_phase == LOGIN_PHASE_START) {
		    list_add(&sendl->list, &ci->sendl_login);
		} else if (ci->login_phase == LOGIN_PHASE_LAST_SEND) {
			/* release login resources */
			dprintf("last login send completed, release, to ff\n");
			iser_free_comm_login(ci);
			ci->login_phase = LOGIN_PHASE_FF;
			break;
		} else {
		    list_add(&sendl->list, &ci->sendl);
		}
		break;

	case IBV_WC_RECV:
		dprintf("incoming cmd, len %d\n", wc->byte_len);
		recvl = ptr_from_int64(wc->wr_id);
		ci = recvl->conn;
		conn = &ci->iscsi_conn;
		--ci->recvl_posted;
		if (conn->state == STATE_CLOSE)
			goto close_err;

		recvl->bytes_recvd = wc->byte_len;
		VALGRIND_MAKE_MEM_DEFINED(recvl->buf, recvl->bytes_recvd);

		/*
		 * Global pointer to the working receive on this connection
		 * for reads from iscsid.c.
		 */
		ci->rcv_comm_event = recvl;
		iscsi_rx_handler(conn);
		ci->rcv_comm_event = NULL;

		if (ci->login_phase == LOGIN_PHASE_LAST_SEND) {
			/* do not repost, just one more send then reinit */
			dprintf("transitioning to full-feature, no repost\n");
			break;
		}

		dprintf("incoming cmd proc done, repost\n");
		ret = ibv_post_recv(ci->qp_hndl, &recvl->wr, &bad_wr);
		if (ret) {
			eprintf("ibv_post_recv failed\n");
			exit(1);
		}
		++ci->recvl_posted;
		break;

	case IBV_WC_RDMA_WRITE:
		dprintf("RDMA write done\n");
		rdmal = ptr_from_int64(wc->wr_id);
		ci = rdmal->conn;
		conn = &ci->iscsi_conn;
		if (conn->state == STATE_CLOSE)
			goto close_err;

		iscsi_rdma_event_modify(conn, EPOLLIN | EPOLLOUT);
		list_add(&rdmal->list, &ci->rdmal);
		if (waiting_rdma_slot) {
			waiting_rdma_slot = 0;
			tgt_add_sched_event(&ci->tx_sched);
		}
		break;

	case IBV_WC_RDMA_READ:
		dprintf("RDMA read done, len %d\n", wc->byte_len);
		rdmal = ptr_from_int64(wc->wr_id);
		ci = rdmal->conn;
		conn = &ci->iscsi_conn;
		if (conn->state == STATE_CLOSE)
			goto close_err;

		assert(rdmal->sge.length == wc->byte_len);
		iser_rdma_read_completion(rdmal);
		list_add(&rdmal->list, &ci->rdmal);
		if (waiting_rdma_slot) {
			waiting_rdma_slot = 0;
			tgt_add_sched_event(&ci->tx_sched);
		}
		break;

	default:
		eprintf("unexpected opcode %d\n", wc->opcode);
		exit(1);
	}

	return;

close_err:
	eprintf("conn state set to closed .. IMPLEMENT ME\n");
	exit(1);
}

/*
 * Could read as many entries as possible without blocking, but
 * that just fills up a list of tasks.  Instead pop out of here
 * so that tx progress, like issuing rdma reads and writes, can
 * happen periodically.
 */
static int iser_poll_cq(struct iser_device *dev, int max_wc)
{
	int ret = 0, numwc = 0;
	struct ibv_wc wc;
	struct conn_info *ci;
	struct recvlist *recvl;

	for (;;) {
		ret = ibv_poll_cq(dev->cq, 1, &wc);
		if (ret < 0) {
			eprintf("ibv_poll_cq %d\n", ret);
			break;
		} else if (ret == 0) {
			break;
		}

		VALGRIND_MAKE_MEM_DEFINED(&wc, sizeof(wc));
		if (wc.status == IBV_WC_SUCCESS) {
			handle_wc(&wc);
			if (++numwc == max_wc) {
				ret = 1;
				break;
			}
		} else if (wc.status == IBV_WC_WR_FLUSH_ERR) {
			recvl = ptr_from_int64(wc.wr_id);
			ci = recvl->conn;
			if (ci->draining) {
				--ci->recvl_posted;
				if (ci->freed && ci->recvl_posted == 0)
					iscsi_rdma_release(&ci->iscsi_conn);
			} else {
				eprintf("conn %p wr flush err\n", ci);
				/* call disconnect now? */
			}
		} else {
			eprintf("bad WC status %d for wr_id 0x%llx\n",
				wc.status, (unsigned long long) wc.wr_id);
		}
	}
	return ret;
}

static void iser_poll_cq_armable(struct iser_device *dev)
{
	int ret;

	ret = iser_poll_cq(dev, MAX_POLL_WC);
	if (ret < 0)
		exit(1);

	if (ret == 0) {
		/* no more completions on cq, arm the completion interrupts */
		ret = ibv_req_notify_cq(dev->cq, 0);
		if (ret) {
			eprintf("ibv_req_notify_cq: %s\n", strerror(ret));
			exit(1);
		}
		dev->poll_sched.sched_handler = iser_sched_consume_cq;
	} else
		dev->poll_sched.sched_handler = iser_sched_poll_cq;

	tgt_add_sched_event(&dev->poll_sched);
}

/* Scheduled to poll cq after a completion event has been
   received and acknowledged, if no more completions are found
   the interrupts are re-armed */
static void iser_sched_poll_cq(struct event_data *tev)
{
	struct iser_device *dev = tev->data;
	iser_poll_cq_armable(dev);
}

/* Scheduled to consume completion events that could arrive
   after the cq had been seen empty but just before
   the notification interrupts were re-armed.
   Intended to consume those remaining completions only,
   this function does not re-arm interrupts. */
static void iser_sched_consume_cq(struct event_data *tev)
{
	struct iser_device *dev = tev->data;
	int ret;

	ret = iser_poll_cq(dev, MAX_POLL_WC);
	if (ret < 0)
		exit(1);
}

/*
 * Called directly from main event loop when a CQ notification is
 * available.
 */
static void iser_cqe_handler(int fd __attribute__((unused)),
			     int events __attribute__((unused)),
			     void *data)
{
	struct iser_device *dev = data;
	void *cq_context;
	int ret;

	ret = ibv_get_cq_event(dev->cq_channel, &dev->cq, &cq_context);
	if (ret != 0) {
		eprintf("notification, but no CQ event\n");
		exit(1);
	}

	ibv_ack_cq_events(dev->cq, 1);

	/* if a poll was previosuly scheduled, remove it,
	   as it will be scheduled when necessary */
	if (dev->poll_sched.scheduled)
		tgt_remove_sched_event(&dev->poll_sched);

	iser_poll_cq_armable(dev);
}

/*
 * Called from tgtd as a scheduled event
 * tries to push tx on a connection, until nothing
 * is ready anymore.  No progress limit here.
 */
static void iser_sched_tx(struct event_data *evt)
{
	struct conn_info *ci = evt->data;
	struct iscsi_connection *conn = &ci->iscsi_conn;
	int ret;

	dprintf("entry\n");

	if (conn->state == STATE_CLOSE) {
		dprintf("ignoring tx for closed conn\n");
		return;
	}

	for (;;) {
		dprintf("trying tx\n");
		ret = iscsi_tx_handler(conn);
		if (conn->state == STATE_CLOSE) {
			conn_close(conn);
			dprintf("connection %p closed\n", ci);
			break;
		}
		if (ret != 0) {
			/* but leave on tx ready list */
			waiting_rdma_slot = 1;
			break;
		}
	}
}

/*
 * Init entire iscsi transport.  Begin listening for connections.
 */
static int iscsi_rdma_init(void)
{
	int ret;
	struct sockaddr_in sock_addr;
	short int port = iscsi_listen_port;

	rdma_evt_channel = rdma_create_event_channel();

	if (!rdma_evt_channel) {
		eprintf("cannot initialize RDMA; load kernel modules?\n");
		return -1;
	}

	ret = rdma_create_id(rdma_evt_channel, &cma_listen_id, NULL,
			     RDMA_PS_TCP);
	if (ret) {
		eprintf("rdma_create_id: %s\n", strerror(ret));
		return -1;
	}

	memset(&sock_addr, 0, sizeof(sock_addr));
	sock_addr.sin_family = AF_INET;
	sock_addr.sin_port = htons(port);
	sock_addr.sin_addr.s_addr = INADDR_ANY;
	ret = rdma_bind_addr(cma_listen_id, (struct sockaddr *) &sock_addr);
	if (ret) {
		if (ret == -1)
			eprintf("rdma_bind_addr -1: %m\n");
		else
			eprintf("rdma_bind_addr: %s\n", strerror(-ret));
		return -1;
	}

	/* 0 == maximum backlog */
	ret = rdma_listen(cma_listen_id, 0);
	if (ret) {
		if (ret == -1)
			eprintf("rdma_listen -1: %m\n");
		else
			eprintf("rdma_listen: %s\n", strerror(-ret));
		return -1;
	}

	dprintf("listening for iser connections on port %d\n", port);
	ret = tgt_event_add(cma_listen_id->channel->fd, EPOLLIN,
			    iser_handle_rdmacm, NULL);
	if (ret)
		return ret;

	INIT_LIST_HEAD(&conn_tx_ready);
	INIT_LIST_HEAD(&iser_dev_list);
	INIT_LIST_HEAD(&iser_conn_list);
	INIT_LIST_HEAD(&temp_conn);

	return ret;
}

/*
 * Allocate resources for this new connection.  Called after login, when
 * final negotiated transfer parameters are known.
 */
static int iscsi_rdma_login_complete(struct iscsi_connection *conn)
{
	int ret = -1;
	struct conn_info *ci = RDMA_CONN(conn);
	unsigned int irdsl, trdsl, outst_pdu, hdrsz;

	dprintf("entry\n");

	/*
	 * Build full feature connection structures, but leave around the
	 * login ones until the final send finishes.
	 */
	ci->login_phase = LOGIN_PHASE_LAST_SEND;  /* one more send, then done */
	irdsl = conn->session_param[ISCSI_PARAM_INITIATOR_RDSL].val;
	trdsl = conn->session_param[ISCSI_PARAM_TARGET_RDSL].val;
	outst_pdu = conn->session_param[ISCSI_PARAM_MAX_OUTST_PDU].val;

	/* hack, ib/ulp/iser does not have this param, but reading the code
	 * shows
	 *    ISCSI_XMIT_CMDS_MAX=128
	 *    ISER_INFLIGHT_DATAOUTS=8
	 *    ISER_MAX_RX_MISC_PDUS=4
	 *    ISER_MAX_TX_MISC_PDUS=6
	 * and their formula for max tx dtos outstanding
	 *    = cmds_max * (1 + dataouts) + rx_misc + tx_misc
	 */
	if (outst_pdu == 0)
		outst_pdu = 128 * (1 + 8) + 6 + 4;

	/* RDSLs do not include headers. */
	hdrsz = sizeof(struct iser_hdr) +
		sizeof(struct iscsi_hdr) +
		sizeof(struct iscsi_ecdb_ahdr) +
		sizeof(struct iscsi_rlength_ahdr);

	ci->ssize = hdrsz + irdsl;
	ci->rsize = hdrsz + trdsl;
	ci->max_outst_pdu = outst_pdu;
	ret = iser_init_comm(ci);
	if (ret)
		eprintf("iser_init_comm failed\n");

	return ret;
}

/*
 * Copy the remote va and stag that were temporarily saved in conn_info.
 */
static struct iscsi_task *iscsi_iser_alloc_task(struct iscsi_connection *conn,
						size_t ext_len)
{
	struct conn_info *ci = RDMA_CONN(conn);
	struct iser_task *itask;

	itask = zalloc(sizeof(*itask) + ext_len);
	if (!itask)
		return NULL;

	itask->rem_read_stag = ci->rem_read_stag;
	itask->rem_read_va = ci->rem_read_va;
	itask->rem_write_stag = ci->rem_write_stag;
	itask->rem_write_va = ci->rem_write_va;

	return &itask->task;
}

static void iscsi_iser_free_task(struct iscsi_task *task)
{
	free(ISER_TASK(task));
}

static int iser_parse_hdr(struct conn_info *ci, struct recvlist *recvl)
{
	int ret = -1;
	struct iser_hdr *hdr = recvl->buf;

	switch (hdr->flags & 0xF0) {
	case ISCSI_CTRL:
		dprintf("control type PDU\n");
		if (hdr->flags & ISER_RSV) {
			ci->rem_read_stag = be32_to_cpu(hdr->read_stag);
			ci->rem_read_va = be64_to_cpu(hdr->read_va);
			dprintf("rstag %x va %llx\n",
				ci->rem_read_stag,
				(unsigned long long) ci->rem_read_va);
		}
		if (hdr->flags & ISER_WSV) {
			ci->rem_write_stag = be32_to_cpu(hdr->write_stag);
			ci->rem_write_va = be64_to_cpu(hdr->write_va);
			dprintf("wstag %x va %llx\n",
				ci->rem_write_stag,
				(unsigned long long) ci->rem_write_va);
		}
		ret = 0;
		break;
	case ISER_HELLO:
		dprintf("iSER Hello message??\n");
		break;
	default:
		eprintf("malformed iser hdr, flags 0x%02x\n", hdr->flags);
		break;
	}

	ci->readb = sizeof(*hdr);
	return ret;
}

static size_t iscsi_iser_read(struct iscsi_connection *conn, void *buf,
			      size_t nbytes)
{
	int ret;
	struct conn_info *ci = RDMA_CONN(conn);
	struct recvlist *recvl;

	dprintf("buf %p nbytes %zu\n", buf, nbytes);
	recvl = ci->rcv_comm_event;
	assert(recvl != NULL);

	if (ci->readb == 0) {
		if (recvl->bytes_recvd < sizeof(struct iser_hdr))
			return 0;

		ret = iser_parse_hdr(ci, recvl);
		if (ret != 0)
			return 0;
	}

	if (ci->readb + nbytes > recvl->bytes_recvd) {
		if (ci->readb > recvl->bytes_recvd)
			nbytes = recvl->bytes_recvd;
		else
			nbytes = recvl->bytes_recvd - ci->readb;
	}

	/* always copy headers into iscsi task structure */
	memcpy(buf, (char *) recvl->buf + ci->readb, nbytes);
	ci->readb += nbytes;

	if (ci->readb == recvl->bytes_recvd)
		ci->readb = 0;

	return nbytes;
}

static size_t iscsi_iser_write_begin(struct iscsi_connection *conn,
				     void *buf, size_t nbytes)
{
	struct conn_info *ci = RDMA_CONN(conn);
	struct sendlist *sendl;

	if (ci->send_comm_event == NULL) {
		/* find one, first time here */
		struct list_head *ci_sendl = &ci->sendl;

		if (ci->login_phase != LOGIN_PHASE_FF)
			ci_sendl = &ci->sendl_login;

		if (list_empty(ci_sendl)) {
			/* bug, max outst pdu should constrain this */
			eprintf("no free send slot\n");
			exit(1);
		}
		sendl = list_entry(ci_sendl->next, typeof(*sendl), list);
		list_del(&sendl->list);
		ci->send_comm_event = sendl;
		dprintf("new sendl %p len %zu\n", sendl, nbytes);
	} else {
		sendl = ci->send_comm_event;
		dprintf("reuse sendl %p len %u + %zu\n", sendl, ci->writeb,
			nbytes);
	}

	if (ci->writeb + nbytes > ci->ssize) {
		eprintf("send buf overflow %d + %zd > %u\n", ci->writeb,
			nbytes, ci->ssize);
		exit(1);
	}

	if (ci->writeb == 0) {
		/* insert iser hdr */
		struct iser_hdr *hdr = sendl->buf;

		memset(hdr, 0, sizeof(*hdr));
		hdr->flags = ISCSI_CTRL;
		ci->writeb = sizeof(*hdr);
	}

	memcpy((char *) sendl->buf + ci->writeb, buf, nbytes);
	ci->writeb += nbytes;
	return nbytes;
}

static void iscsi_iser_write_end(struct iscsi_connection *conn)
{
	int ret;
	struct ibv_send_wr *bad_wr;
	struct conn_info *ci = RDMA_CONN(conn);
	struct sendlist *sendl;

	sendl = ci->send_comm_event;  /* set from _write_begin above */
	dprintf("sendl %p len %d\n", sendl, ci->writeb);

	sendl->sge.length = ci->writeb;

	ret = ibv_post_send(ci->qp_hndl, &sendl->wr, &bad_wr);
	if (ret) {
		/* bug, should have sized max_outst_pdu properly */
		eprintf("ibv_post_send ret %d\n", ret);
		exit(1);
	}

	ci->writeb = 0;  /* reset count */
	ci->send_comm_event = NULL;
}

/*
 * Expected opcodes are: IBV_WR_RDMA_WRITE, IBV_WR_RDMA_READ.
 */
static int iser_post_rdma_wr(struct conn_info *ci, struct iscsi_task *task,
			     void *buf, ssize_t size, int op,
			     uint64_t remote_va, uint32_t remote_rkey)
{
	int ret;
	struct rdmalist *rdmal;
	struct ibv_send_wr *bad_wr;

	if (list_empty(&ci->rdmal)) {
		eprintf("no slot\n");
		return -1;
	}
	rdmal = list_entry(ci->rdmal.next, typeof(*rdmal), list);
	list_del(&rdmal->list);

	rdmal->task = task;
	rdmal->sge.addr = uint64_from_ptr(buf);
	rdmal->sge.length = size;

	rdmal->wr.opcode = op;
	rdmal->wr.wr.rdma.remote_addr = remote_va;
	rdmal->wr.wr.rdma.rkey = remote_rkey;

	ret = ibv_post_send(ci->qp_hndl, &rdmal->wr, &bad_wr);
	if (ret)
		eprintf("ibv_post_send ret %d\n", ret);

	return ret;
}

/*
 * Convert the iscsi r2t request to an RDMA read and post it.
 */
static int iscsi_rdma_rdma_read(struct iscsi_connection *conn)
{
	struct conn_info *ci = RDMA_CONN(conn);
	struct iscsi_task *task = conn->tx_task;
	struct iser_task *itask = ISER_TASK(task);
	struct iscsi_r2t_rsp *r2t = (struct iscsi_r2t_rsp *) &conn->rsp.bhs;
	uint8_t *buf;
	uint32_t len;
	int ret;

	buf = (uint8_t *) task->data + task->offset;
	len = be32_to_cpu(r2t->data_length);

	dprintf("len %u stag %x va %llx\n",
		len, itask->rem_write_stag,
		(unsigned long long) itask->rem_write_va);

	ret = iser_post_rdma_wr(ci, task, buf, len, IBV_WR_RDMA_READ,
				itask->rem_write_va, itask->rem_write_stag);
	if (ret < 0)
		return ret;

	/*
	 * Initiator registers the entire buffer, but gives us a VA that
	 * is advanced by immediate + unsolicited data amounts.  Advance
	 * rem_va as we read, knowing that the target always grabs segments
	 * in order.
	 */
	itask->rem_write_va += len;

	return 0;
}

/*
 * Convert the iscsi data-in response to an RDMA write and send it.
 */
static int iscsi_rdma_rdma_write(struct iscsi_connection *conn)
{
	struct conn_info *ci = RDMA_CONN(conn);
	struct iscsi_task *task = conn->tx_task;
	struct iser_task *itask = ISER_TASK(task);
	struct iscsi_pdu *rsp = &conn->rsp;
	struct iscsi_data_rsp *datain = (struct iscsi_data_rsp *) &rsp->bhs;
	uint32_t offset;
	int ret;

	offset = be32_to_cpu(datain->offset);

	dprintf("offset %d len %d stag %x va %llx\n", offset, rsp->datasize,
		itask->rem_read_stag, (unsigned long long) itask->rem_read_va);

	ret = iser_post_rdma_wr(ci, task, rsp->data, rsp->datasize,
				IBV_WR_RDMA_WRITE, itask->rem_read_va + offset,
				itask->rem_read_stag);
	if (ret < 0)
		return ret;

	/*
	 * iscsi thinks we are txing, but really we're waiting for this
	 * rdma to finish before sending the completion.  Then we'll stick
	 * ourselves back on the list.
	 */
	if (task->offset == task->len) {
		iscsi_rdma_event_modify(conn, EPOLLIN);
	} else {
		/* poke ourselves to do the next rdma */
		tgt_add_sched_event(&ci->tx_sched);
	}

	return ret;
}

/*
 * Called from CQ processing.  Hands completed write data to iscsi.
 */
static void iser_rdma_read_completion(struct rdmalist *rdmal)
{
	struct conn_info *ci = rdmal->conn;
	struct iscsi_connection *conn = &ci->iscsi_conn;
	struct iscsi_task *task;

	/* task is no longer conn->tx_task, look it up */
	list_for_each_entry(task, &conn->session->cmd_list, c_hlist) {
		if (task == rdmal->task)
			goto found;
	}
	eprintf("no task\n");
	return;

found:
	/* equivalent of iscsi_data_out_rx_start + _done */
	conn->rx_buffer = ptr_from_int64(rdmal->sge.addr);
	conn->rx_size = rdmal->sge.length;
	task->offset += rdmal->sge.length;
	task->r2t_count -= rdmal->sge.length;
	VALGRIND_MAKE_MEM_DEFINED(conn->rx_buffer, conn->rx_size);

	dprintf("itt %x len %u arrived, r2t_count %d\n", (uint32_t) task->tag,
		rdmal->sge.length, task->r2t_count);

	/*
	 * We soliticed this data, so hdr->ttt is what we asked for.  Bypass
	 * data_out_rx_done and just run the task.  If more r2t are needed,
	 * this will generate them.
	 */
	iscsi_scsi_cmd_execute(task);

	conn->rx_task = NULL;
	conn_read_pdu(conn);
}

/*
 * Close connection.  There is no device close function.  This is called
 * from iscsi.
 */
static size_t iscsi_rdma_close(struct iscsi_connection *conn)
{
	struct conn_info *ci = RDMA_CONN(conn);
	int ret;

	ret = rdma_disconnect(ci->cma_id);
	if (ret)
		eprintf("rdma_disconnect: %s\n", strerror(-ret));
	dprintf("did rdma_disconnect\n");
	list_del(&ci->conn_tx_ready);
	list_del(&ci->iser_conn_list);
	ci->draining = 1;
	return 0;
}

/*
 * Called when the connection is freed, from iscsi, but won't do anything until
 * all posted WRs have gone away.  So also called again from RX progress when
 * it notices this happens.
 */
static void iscsi_rdma_release(struct iscsi_connection *conn)
{
	struct conn_info *ci = RDMA_CONN(conn);
	int ret;

	dprintf("conn %p recvl %d\n", ci, ci->recvl_posted);

	ci->freed = 1;

	/* wait until all WRs flushed */
	if (ci->recvl_posted != 0)
		return;

	iser_free_comm_login(ci);
	if (ci->login_phase == LOGIN_PHASE_FF)
		iser_free_comm(ci);

	/* finally destory QP */
	ret = ibv_destroy_qp(ci->qp_hndl);
	if (ret)
		eprintf("ibv_destroy_qp: %s\n", strerror(-ret));

	/* and free the connection */
	conn_exit(conn);
	free(ci);
}

static int iscsi_rdma_show(struct iscsi_connection *conn, char *buf,
			   int rest)
{
	int ret;
	char host[NI_MAXHOST];
	struct conn_info *ci = RDMA_CONN(conn);

	ret = getnameinfo((struct sockaddr *) &ci->peer_addr,
			  sizeof(ci->peer_addr), host, sizeof(host), NULL, 0,
			  NI_NUMERICHOST);
	if (ret) {
		eprintf("getnameinfo: %m\n");
		return 0;
	}
	return snprintf(buf, rest, "RDMA IP Address: %s", host);
}

static void iscsi_rdma_event_modify(struct iscsi_connection *conn, int events)
{
	struct conn_info *ci = RDMA_CONN(conn);

	if (events & EPOLLOUT) {
		/* with multiple commands queued, may already be on list */
		if (list_empty(&ci->conn_tx_ready)) {
			dprintf("tx ready adding %p\n", ci);
			list_add(&ci->conn_tx_ready, &conn_tx_ready);
		}
		tgt_add_sched_event(&ci->tx_sched);
	} else {
		dprintf("tx ready removing %p\n", ci);
		list_del_init(&ci->conn_tx_ready);
	}
}

static void *iscsi_rdma_alloc_data_buf(struct iscsi_connection *conn,
				       size_t sz)
{
	struct mempool *mem;
	struct conn_info *ci = RDMA_CONN(conn);
	struct iser_device *dev = ci->dev;

	if (list_empty(&dev->mempool_free)) {
		/* XXX: take slow path: allocate and register */
		eprintf("free list empty\n");
		exit(1);
	}

	if (sz > mempool_size) {
		eprintf("size %zu too big\n", sz);
		exit(1);
	}

	mem = list_entry(dev->mempool_free.next, typeof(*mem), list);
	list_del(&mem->list);
	list_add(&mem->list, &dev->mempool_alloc);
	dprintf("malloc %p sz %zu\n", mem->buf, sz);
	return mem->buf;
}

static void iscsi_rdma_free_data_buf(struct iscsi_connection *conn, void *buf)
{
	int found = 0;
	struct mempool *mem;
	struct conn_info *ci = RDMA_CONN(conn);
	struct iser_device *dev = ci->dev;

	if (!buf)
		return;
	list_for_each_entry(mem, &dev->mempool_alloc, list) {
		if (mem->buf == buf) {
			found = 1;
			break;
		}
	}
	dprintf("free %p\n", mem->buf);
	if (!found) {
		eprintf("couldn't locate buf %p\n", buf);
		exit(1);
	}
	list_del(&mem->list);
	list_add(&mem->list, &dev->mempool_free);
}

static int iscsi_rdma_getsockname(struct iscsi_connection *conn,
				  struct sockaddr *sa, socklen_t *len)
{
	struct conn_info *ci = RDMA_CONN(conn);

	if (*len > sizeof(ci->self_addr))
		*len = sizeof(ci->self_addr);
	memcpy(sa, &ci->self_addr, *len);
	return 0;
}

static int iscsi_rdma_getpeername(struct iscsi_connection *conn,
				  struct sockaddr *sa, socklen_t *len)
{
	struct conn_info *ci = RDMA_CONN(conn);

	if (*len > sizeof(ci->peer_addr))
		*len = sizeof(ci->peer_addr);
	memcpy(sa, &ci->peer_addr, *len);
	return 0;
}

static struct iscsi_transport iscsi_iser = {
	.name			= "iser",
	.rdma			= 1,
	.data_padding		= 1,
	.ep_init		= iscsi_rdma_init,
	.ep_login_complete	= iscsi_rdma_login_complete,
	.alloc_task		= iscsi_iser_alloc_task,
	.free_task		= iscsi_iser_free_task,
	.ep_read		= iscsi_iser_read,
	.ep_write_begin		= iscsi_iser_write_begin,
	.ep_write_end		= iscsi_iser_write_end,
	.ep_rdma_read		= iscsi_rdma_rdma_read,
	.ep_rdma_write		= iscsi_rdma_rdma_write,
	.ep_close		= iscsi_rdma_close,
	.ep_release		= iscsi_rdma_release,
	.ep_show		= iscsi_rdma_show,
	.ep_event_modify	= iscsi_rdma_event_modify,
	.alloc_data_buf		= iscsi_rdma_alloc_data_buf,
	.free_data_buf		= iscsi_rdma_free_data_buf,
	.ep_getsockname		= iscsi_rdma_getsockname,
	.ep_getpeername		= iscsi_rdma_getpeername,
};

__attribute__((constructor)) static void iser_transport_init(void)
{
	iscsi_transport_register(&iscsi_iser);
}
