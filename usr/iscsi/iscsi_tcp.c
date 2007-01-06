/*
 * Software iSCSI target over TCP/IP Data-Path
 *
 * (C) 2006 FUJITA Tomonori <tomof@acm.org>
 * (C) 2006 Mike Christie <michaelc@cs.wisc.edu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
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

static void accept_connection(int afd, int events, void *data)
{
	struct sockaddr_storage from;
	socklen_t namesize;
	struct iscsi_connection *conn;
	int fd, err;

	dprintf("%d\n", afd);

	namesize = sizeof(from);
	fd = accept(afd, (struct sockaddr *) &from, &namesize);
	if (fd < 0) {
		eprintf("can't accept, %m\n");
		return;
	}

	conn = conn_alloc();
	if (!conn)
		goto out;

	conn->fd = fd;
	conn->tp = &iscsi_tcp;

	conn_read_pdu(conn);
	set_non_blocking(fd);

	err = tgt_event_add(fd, EPOLLIN, iscsi_event_handler, conn);
	if (err)
		goto free_conn;

	return;
free_conn:
	free(conn);
out:
	close(fd);
	return;
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

static size_t iscsi_tcp_read (int ep, void *buf, size_t nbytes)
{
	return read(ep, buf, nbytes);
}

static size_t iscsi_tcp_write_begin(int ep, void *buf, size_t nbytes)
{
	int opt = 1;
	setsockopt(ep, SOL_TCP, TCP_CORK, &opt, sizeof(opt));
	return write(ep, buf, nbytes);
}

static void iscsi_tcp_write_end(int ep)
{
	int opt = 0;
	setsockopt(ep, SOL_TCP, TCP_CORK, &opt, sizeof(opt));
}

static size_t iscsi_tcp_close(int ep)
{
	return close(ep);
}

static int iscsi_tcp_show(int ep, char *buf, int rest)
{
	int err, total = 0;
	socklen_t slen;
	char dst[INET6_ADDRSTRLEN];
	struct sockaddr_storage from;

	slen = sizeof(from);
	err = getpeername(ep, (struct sockaddr *) &from, &slen);
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

struct iscsi_transport iscsi_tcp = {
	.name		= "iscsi",
	.rdma		= 0,
	.ep_init	= iscsi_tcp_init,
	.ep_read	= iscsi_tcp_read,
	.ep_write_begin	= iscsi_tcp_write_begin,
	.ep_write_end	= iscsi_tcp_write_end,
	.ep_close	= iscsi_tcp_close,
	.ep_show	= iscsi_tcp_show,
};
