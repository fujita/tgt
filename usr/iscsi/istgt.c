/*
 * Software iSCSI target library
 *
 * (C) 2005-2006 FUJITA Tomonori <tomof@acm.org>
 * (C) 2005-2006 Mike Christie <michaelc@cs.wisc.edu>
 *
 * This code is based on Ardis's iSCSI implementation.
 *   http://www.ardistech.com/iscsi/
 *   Copyright (C) 2002-2003 Ardis Technolgies <roman@ardistech.com>,
 *   licensed under the terms of the GNU GPL v2.0,
 */
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <netdb.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/epoll.h>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include "iscsid.h"
#include "tgtd.h"

#define ISCSI_LISTEN_PORT	3260
#define LISTEN_MAX		4
#define INCOMING_MAX		32

static void set_non_blocking(int fd)
{
	int err;

	err = fcntl(fd, F_GETFL);
	if (err < 0) {
		eprintf("unable to get fd flags, %m\n");
	} else {
		err = fcntl(fd, F_SETFL, err | O_NONBLOCK);
		if (err == -1)
			eprintf("unable to set fd flags, %m\n");
	}
}

static void iscsi_rx_handler(int fd, struct connection *conn)
{
	int res;

	switch (conn->rx_iostate) {
	case IOSTATE_READ_BHS:
	case IOSTATE_READ_AHS_DATA:
	read_again:
		res = read(fd, conn->rx_buffer, conn->rx_size);
		if (res <= 0) {
			if (res == 0 || (errno != EINTR && errno != EAGAIN))
				conn->state = STATE_CLOSE;
			else if (errno == EINTR)
				goto read_again;
			break;
		}
		conn->rx_size -= res;
		conn->rx_buffer += res;
		if (conn->rx_size)
			break;

		switch (conn->rx_iostate) {
		case IOSTATE_READ_BHS:
			conn->rx_iostate = IOSTATE_READ_AHS_DATA;
			conn->req.ahssize = conn->req.bhs.hlength * 4;
			conn->req.datasize = ntoh24(conn->req.bhs.dlength);
			conn->rx_size = (conn->req.ahssize + conn->req.datasize + 3) & -4;

			if (conn->req.ahssize) {
				eprintf("FIXME: we cannot handle ahs\n");
				conn->state = STATE_CLOSE;
				break;
			}

			if (conn->state == STATE_SCSI) {
				res = iscsi_cmd_rx_start(conn);
				if (res) {
					conn->state = STATE_CLOSE;
					break;
				}
			}

			if (conn->rx_size) {
				if (conn->state != STATE_SCSI) {
					conn->rx_buffer = conn->req_buffer;
					conn->req.ahs = conn->rx_buffer;
				}
				conn->req.data =
					conn->rx_buffer + conn->req.ahssize;
				goto read_again;
			}

		case IOSTATE_READ_AHS_DATA:
			if (conn->state == STATE_SCSI) {
				res = iscsi_cmd_rx_done(conn);
				if (!res)
					conn_read_pdu(conn);
			} else {
				conn_write_pdu(conn);
				tgt_event_modify(fd, EPOLLOUT);
				res = cmnd_execute(conn);
			}

			if (res)
				conn->state = STATE_CLOSE;
			break;
		}
		break;
	}
}

static void iscsi_tx_handler(int fd, struct connection *conn)
{
	int res, opt;

	if (conn->state == STATE_SCSI && !conn->tx_ctask) {
		res = iscsi_cmd_tx_start(conn);
		if (res)
			return;
	}

	switch (conn->tx_iostate) {
	case IOSTATE_WRITE_BHS:
	case IOSTATE_WRITE_AHS:
	case IOSTATE_WRITE_DATA:
	write_again:
		opt = 1;
		setsockopt(fd, SOL_TCP, TCP_CORK, &opt, sizeof(opt));
		res = write(fd, conn->tx_buffer, conn->tx_size);
		if (res < 0) {
			if (errno != EINTR && errno != EAGAIN)
				conn->state = STATE_CLOSE;
			else if (errno == EINTR)
				goto write_again;
			break;
		}

		conn->tx_size -= res;
		conn->tx_buffer += res;
		if (conn->tx_size)
			goto write_again;

		switch (conn->tx_iostate) {
		case IOSTATE_WRITE_BHS:
			if (conn->rsp.ahssize) {
				conn->tx_iostate = IOSTATE_WRITE_AHS;
				conn->tx_buffer = conn->rsp.ahs;
				conn->tx_size = conn->rsp.ahssize;
				goto write_again;
			}
		case IOSTATE_WRITE_AHS:
			if (conn->rsp.datasize) {
				int pad;

				conn->tx_iostate = IOSTATE_WRITE_DATA;
				conn->tx_buffer = conn->rsp.data;
				conn->tx_size = conn->rsp.datasize;
				pad = conn->tx_size & (PAD_WORD_LEN - 1);
				if (pad) {
					memset(conn->tx_buffer + conn->tx_size,
					       0, pad);
					conn->tx_size += pad;
				}
				goto write_again;
			}
		case IOSTATE_WRITE_DATA:
			opt = 0;
			setsockopt(fd, SOL_TCP, TCP_CORK, &opt, sizeof(opt));
			cmnd_finish(conn);

			switch (conn->state) {
			case STATE_KERNEL:
				res = conn_take_fd(conn, fd);
				if (res)
					conn->state = STATE_CLOSE;
				else {
					conn->state = STATE_SCSI;
					conn_read_pdu(conn);
					tgt_event_modify(fd, EPOLLIN);
				}
				break;
			case STATE_EXIT:
			case STATE_CLOSE:
				break;
			case STATE_SCSI:
				iscsi_cmd_tx_done(conn);
				break;
			default:
				conn_read_pdu(conn);
				tgt_event_modify(fd, EPOLLIN);
				break;
			}
			break;
		}

		break;
	default:
		eprintf("illegal iostate %d %d\n", conn->tx_iostate,
			conn->tx_iostate);
		conn->state = STATE_CLOSE;
	}

}

static void iscsi_event_handler(int fd, int events, void *data)
{
	struct connection *conn = (struct connection *) data;

	if (events & EPOLLIN)
		iscsi_rx_handler(fd, conn);

	if (conn->state == STATE_CLOSE)
		dprintf("connection closed\n");

	if (conn->state != STATE_CLOSE && events & EPOLLOUT)
		iscsi_tx_handler(fd, conn);

	if (conn->state == STATE_CLOSE) {
		dprintf("connection closed\n");
		conn_free(conn);
		tgt_event_del(fd);
		close(fd);
	}
}

static void accept_connection(int afd, int events, void *data)
{
	struct sockaddr_storage from;
	socklen_t namesize;
	struct connection *conn;
	int fd, err;

	eprintf("%d\n", afd);

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

int iscsi_init(void)
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
