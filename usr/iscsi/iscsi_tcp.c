/*
 * Software iSCSI target over TCP/IP Data-Path
 *
 * Copyright (C) 2006-2007 FUJITA Tomonori <tomof@acm.org>
 * Copyright (C) 2006-2007 Mike Christie <michaelc@cs.wisc.edu>
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
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/socket.h>

#include "iscsid.h"
#include "tgtd.h"
#include "util.h"

#define ISCSI_LISTEN_PORT	3260
#define LISTEN_MAX		4
#define INCOMING_MAX		32

static void iscsi_tcp_event_handler(int fd, int events, void *data);

struct tcp_conn_info {
	int fd;
};

static int set_keepalive(int fd)
{
	int ret, opt;

	opt = 1;
	ret = setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt));
	if (ret)
		return ret;

	opt = 1800;
	ret = setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &opt, sizeof(opt));
	if (ret)
		return ret;

	opt = 6;
	ret = setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &opt, sizeof(opt));
	if (ret)
		return ret;

	opt = 300;
	ret = setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &opt, sizeof(opt));
	if (ret)
		return ret;

	return 0;
}

static void accept_connection(int afd, int events, void *data)
{
	struct sockaddr_storage from;
	socklen_t namesize;
	struct iscsi_connection *conn;
	struct tcp_conn_info *tci;
	int fd, err;

	dprintf("%d\n", afd);

	namesize = sizeof(from);
	fd = accept(afd, (struct sockaddr *) &from, &namesize);
	if (fd < 0) {
		eprintf("can't accept, %m\n");
		return;
	}

	err = set_keepalive(fd);
	if (err)
		goto out;

	conn = conn_alloc(sizeof(*tci));
	if (!conn)
		goto out;

	tci = conn->trans_data;
	tci->fd = fd;
	conn->tp = &iscsi_tcp;

	conn_read_pdu(conn);
	set_non_blocking(fd);

	err = tgt_event_add(fd, EPOLLIN, iscsi_tcp_event_handler, conn);
	if (err)
		goto free_conn;

	return;
free_conn:
	free(conn);
out:
	close(fd);
	return;
}

static void iscsi_tcp_event_handler(int fd, int events, void *data)
{
	struct iscsi_connection *conn = (struct iscsi_connection *) data;

	if (events & EPOLLIN)
		iscsi_rx_handler(conn);

	if (conn->state == STATE_CLOSE)
		dprintf("connection closed\n");

	if (conn->state != STATE_CLOSE && events & EPOLLOUT)
		iscsi_tx_handler(conn);

	if (conn->state == STATE_CLOSE) {
		conn_close(conn);
		dprintf("connection closed\n");
	}
}

static int iscsi_tcp_init(void)
{
	struct addrinfo hints, *res, *res0;
	char servname[64];
	int err, i, fd, opt, nr_sock = 0;

	memset(servname, 0, sizeof(servname));
	snprintf(servname, sizeof(servname), "%d", ISCSI_LISTEN_PORT);

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	err = getaddrinfo(NULL, servname, &hints, &res0);
	if (err) {
		eprintf("unable to get address info, %m\n");
		return -errno;
	}

	for (i = 0, res = res0; res && i < LISTEN_MAX; i++, res = res->ai_next) {
		fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (fd < 0) {
			if (res->ai_family == AF_INET6)
				dprintf("IPv6 support is disabled.\n");
			else
				eprintf("unable to create fdet %d %d %d, %m\n",
					res->ai_family,	res->ai_socktype,
					res->ai_protocol);
			continue;
		}

		opt = 1;
		err = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt,
				 sizeof(opt));
		if (err)
			dprintf("unable to set SO_REUSEADDR, %m\n");

		opt = 1;
		if (res->ai_family == AF_INET6) {
			err = setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &opt,
					 sizeof(opt));
			if (err) {
				close(fd);
				continue;
			}
		}

		err = bind(fd, res->ai_addr, res->ai_addrlen);
		if (err) {
			close(fd);
			eprintf("unable to bind server socket, %m\n");
			continue;
		}

		err = listen(fd, INCOMING_MAX);
		if (err) {
			eprintf("unable to listen to server socket, %m\n");
			close(fd);
			continue;
		}

		set_non_blocking(fd);
		err = tgt_event_add(fd, EPOLLIN, accept_connection, NULL);
		if (err)
			close(fd);
		else
			nr_sock++;
	}

	freeaddrinfo(res0);

	return !nr_sock;
}

static size_t iscsi_tcp_read(struct iscsi_connection *conn, void *buf,
			     size_t nbytes)
{
	struct tcp_conn_info *tci = conn->trans_data;
	return read(tci->fd, buf, nbytes);
}

static size_t iscsi_tcp_write_begin(struct iscsi_connection *conn, void *buf,
				    size_t nbytes)
{
	struct tcp_conn_info *tci = conn->trans_data;
	int opt = 1;

	setsockopt(tci->fd, SOL_TCP, TCP_CORK, &opt, sizeof(opt));
	return write(tci->fd, buf, nbytes);
}

static void iscsi_tcp_write_end(struct iscsi_connection *conn)
{
	struct tcp_conn_info *tci = conn->trans_data;
	int opt = 0;

	setsockopt(tci->fd, SOL_TCP, TCP_CORK, &opt, sizeof(opt));
}

static size_t iscsi_tcp_close(struct iscsi_connection *conn)
{
	struct tcp_conn_info *tci = conn->trans_data;

	tgt_event_del(tci->fd);
	return close(tci->fd);
}

static int iscsi_tcp_show(struct iscsi_connection *conn, char *buf, int rest)
{
	struct tcp_conn_info *tci = conn->trans_data;
	int err, total = 0;
	socklen_t slen;
	char dst[INET6_ADDRSTRLEN];
	struct sockaddr_storage from;

	slen = sizeof(from);
	err = getpeername(tci->fd, (struct sockaddr *) &from, &slen);
	if (err < 0) {
		eprintf("%m\n");
		return 0;
	}

	err = getnameinfo((struct sockaddr *)&from, sizeof(from), dst,
			  sizeof(dst), NULL, 0, NI_NUMERICHOST);
	if (err < 0) {
		eprintf("%m\n");
		return 0;
	}

	total = snprintf(buf, rest, "IP Address: %s", dst);

	return total > 0 ? total : 0;
}

void iscsi_event_modify(struct iscsi_connection *conn, int events)
{
	int ret;
	struct tcp_conn_info *tci = conn->trans_data;

	ret = tgt_event_modify(tci->fd, events);
	if (ret)
		eprintf("tgt_event_modify failed\n");
}

void *iscsi_tcp_alloc_data_buf(struct iscsi_connection *conn, size_t sz)
{
	return valloc(sz);
}

void iscsi_tcp_free_data_buf(struct iscsi_connection *conn, void *buf)
{
	if (buf)
		free(buf);
}

int iscsi_tcp_getsockname(struct iscsi_connection *conn, struct sockaddr *sa,
			  socklen_t *len)
{
	struct tcp_conn_info *tci = conn->trans_data;

	return getsockname(tci->fd, sa, len);
}

int iscsi_tcp_getpeername(struct iscsi_connection *conn, struct sockaddr *sa,
			  socklen_t *len)
{
	struct tcp_conn_info *tci = conn->trans_data;

	return getpeername(tci->fd, sa, len);
}

struct iscsi_transport iscsi_tcp = {
	.name			= "iscsi",
	.rdma			= 0,
	.ep_init		= iscsi_tcp_init,
	.ep_read		= iscsi_tcp_read,
	.ep_write_begin		= iscsi_tcp_write_begin,
	.ep_write_end		= iscsi_tcp_write_end,
	.ep_close		= iscsi_tcp_close,
	.ep_show		= iscsi_tcp_show,
	.ep_event_modify	= iscsi_event_modify,
	.alloc_data_buf		= iscsi_tcp_alloc_data_buf,
	.free_data_buf		= iscsi_tcp_free_data_buf,
	.ep_getsockname		= iscsi_tcp_getsockname,
	.ep_getpeername		= iscsi_tcp_getpeername,
};
