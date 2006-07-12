/*
 * Software iSCSI target library
 *
 * (C) 2005 FUJITA Tomonori <tomof@acm.org>
 * (C) 2005 Mike Christie <michaelc@cs.wisc.edu>
 * This code is licenced under the GPL.
 *
 * This is based on Ardis's iSCSI implementation.
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

#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include "iscsid.h"

#define ISCSI_LISTEN_PORT	3260

#define LISTEN_MAX	4
#define INCOMING_MAX	32

enum {
	POLL_LISTEN,
	POLL_NL = POLL_LISTEN + LISTEN_MAX,
	POLL_INCOMING,
	POLL_MAX = POLL_INCOMING + INCOMING_MAX,
};

static struct connection *incoming[INCOMING_MAX];
uint64_t thandle;
int nl_fd;

static void set_non_blocking(int fd)
{
	int res = fcntl(fd, F_GETFL);

	if (res != -1) {
		res = fcntl(fd, F_SETFL, res | O_NONBLOCK);
		if (res)
			dprintf("unable to set fd flags (%s)!\n", strerror(errno));
	} else
		dprintf("unable to get fd flags (%s)!\n", strerror(errno));
}

static void listen_socket_create(struct pollfd *pfds)
{
	struct addrinfo hints, *res, *res0;
	char servname[64];
	int i, sock, opt;

	memset(servname, 0, sizeof(servname));
	snprintf(servname, sizeof(servname), "%d", ISCSI_LISTEN_PORT);

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	if (getaddrinfo(NULL, servname, &hints, &res0)) {
		eprintf("unable to get address info (%s)!\n", strerror(errno));
		exit(1);
	}

	for (i = 0, res = res0; res && i < LISTEN_MAX; i++, res = res->ai_next) {
		sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (sock < 0) {
			eprintf("unable to create server socket (%s) %d %d %d!\n",
				  strerror(errno), res->ai_family,
				  res->ai_socktype, res->ai_protocol);
			continue;
		}

		opt = 1;
		if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)))
			dprintf("unable to set SO_REUSEADDR on server socket (%s)!\n",
				    strerror(errno));
		opt = 1;
		if (res->ai_family == AF_INET6 &&
		    setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt)))
			continue;

		if (bind(sock, res->ai_addr, res->ai_addrlen)) {
			eprintf("unable to bind server socket (%s)!\n", strerror(errno));
			continue;
		}

		if (listen(sock, INCOMING_MAX)) {
			eprintf("unable to listen to server socket (%s)!\n", strerror(errno));
			continue;
		}

		set_non_blocking(sock);

		pfds[i].fd = sock;
		pfds[i].events = POLLIN;
	}

	freeaddrinfo(res0);
}

static void accept_connection(struct pollfd *pfds, int afd)
{
	struct sockaddr_storage from;
	socklen_t namesize;
	struct pollfd *pfd;
	struct connection *conn;
	int fd, i;

	eprintf("%d\n", afd);

	namesize = sizeof(from);
	if ((fd = accept(afd, (struct sockaddr *) &from, &namesize)) < 0) {
		if (errno != EINTR && errno != EAGAIN) {
			eprintf("accept(incoming_socket)\n");
			exit(1);
		}
		return;
	}

	for (i = 0; i < INCOMING_MAX; i++) {
		if (!incoming[i])
			break;
	}
	if (i >= INCOMING_MAX) {
		eprintf("unable to find incoming slot? %d\n", i);
		goto out;
	}

	conn = conn_alloc();
	if (!conn) {
		eprintf("fail to allocate conn\n");
		goto out;
	}
	conn->fd = fd;
	incoming[i] = conn;
	conn_read_pdu(conn);

	set_non_blocking(fd);
	pfd = &pfds[POLL_INCOMING + i];
	pfd->fd = fd;
	pfd->events = POLLIN;
	pfd->revents = 0;

	return;
out:
	close(fd);
	return;
}

void iscsi_event_handle(struct pollfd *pfds)
{
	struct connection *conn;
	struct pollfd *pfd;
	int i, res, opt;

	for (i = 0; i < LISTEN_MAX; i++) {
		if (pfds[POLL_LISTEN + i].revents)
			accept_connection(pfds, pfds[POLL_LISTEN + i].fd);
	}

	for (i = 0; i < INCOMING_MAX; i++) {
		conn = incoming[i];
		pfd = &pfds[POLL_INCOMING + i];
		if (!conn || !pfd->revents)
			continue;

		pfd->revents = 0;

		switch (conn->iostate) {
		case IOSTATE_READ_BHS:
		case IOSTATE_READ_AHS_DATA:
		read_again:
			res = read(pfd->fd, conn->buffer, conn->rwsize);
			if (res <= 0) {
				if (res == 0 || (errno != EINTR && errno != EAGAIN))
					conn->state = STATE_CLOSE;
				else if (errno == EINTR)
					goto read_again;
				break;
			}
			conn->rwsize -= res;
			conn->buffer += res;
			if (conn->rwsize)
				break;

			switch (conn->iostate) {
			case IOSTATE_READ_BHS:
				conn->iostate = IOSTATE_READ_AHS_DATA;
				conn->req.ahssize =
					conn->req.bhs.hlength * 4;
				conn->req.datasize =
					ntoh24(conn->req.bhs.dlength);
				conn->rwsize = (conn->req.ahssize + conn->req.datasize + 3) & -4;
				if (conn->rwsize) {
					if (!conn->req_buffer)
						conn->req_buffer = malloc(INCOMING_BUFSIZE);
					conn->buffer = conn->req_buffer;
					conn->req.ahs = conn->buffer;
					conn->req.data = conn->buffer + conn->req.ahssize;
					goto read_again;
				}

			case IOSTATE_READ_AHS_DATA:
				conn_write_pdu(conn);
				pfd->events = POLLOUT;

				if (!cmnd_execute(conn))
					conn->state = STATE_CLOSE;
				break;
			}
			break;

		case IOSTATE_WRITE_BHS:
		case IOSTATE_WRITE_AHS:
		case IOSTATE_WRITE_DATA:
		write_again:
			opt = 1;
			setsockopt(pfd->fd, SOL_TCP, TCP_CORK, &opt, sizeof(opt));
			res = write(pfd->fd, conn->buffer, conn->rwsize);
			if (res < 0) {
				if (errno != EINTR && errno != EAGAIN)
					conn->state = STATE_CLOSE;
				else if (errno == EINTR)
					goto write_again;
				break;
			}

			conn->rwsize -= res;
			conn->buffer += res;
			if (conn->rwsize)
				goto write_again;

			switch (conn->iostate) {
			case IOSTATE_WRITE_BHS:
				if (conn->rsp.ahssize) {
					conn->iostate = IOSTATE_WRITE_AHS;
					conn->buffer = conn->rsp.ahs;
					conn->rwsize = conn->rsp.ahssize;
					goto write_again;
				}
			case IOSTATE_WRITE_AHS:
				if (conn->rsp.datasize) {
					int o;

					conn->iostate = IOSTATE_WRITE_DATA;
					conn->buffer = conn->rsp.data;
					conn->rwsize = conn->rsp.datasize;
					o = conn->rwsize & 3;
					if (o) {
						for (o = 4 - o; o; o--)
							*((uint8_t *)conn->buffer + conn->rwsize++) = 0;
					}
					goto write_again;
				}
			case IOSTATE_WRITE_DATA:
				opt = 0;
				setsockopt(pfd->fd, SOL_TCP, TCP_CORK, &opt, sizeof(opt));
				cmnd_finish(conn);

				switch (conn->state) {
				case STATE_KERNEL:
					conn_take_fd(conn, pfd->fd);
					conn->state = STATE_CLOSE;
					break;
				case STATE_EXIT:
				case STATE_CLOSE:
					break;
				default:
					conn_read_pdu(conn);
					pfd->events = POLLIN;
					break;
				}
				break;
			}

			break;
		default:
			eprintf("illegal iostate %d for port %d!\n", conn->iostate, i);
			exit(1);
		}

		if (conn->state == STATE_CLOSE) {
			dprintf("connection closed\n");
			conn_free_pdu(conn);
			conn_free(conn);
/* 			close(pfd->fd); */
			pfd->fd = -1;
			incoming[i] = NULL;
		}
	}
}

int iscsi_poll_init(struct pollfd *pfd)
{
	int i;

	pfd[POLL_NL].fd = nl_fd;
	pfd[POLL_NL].events = POLLIN;

	listen_socket_create(pfd + POLL_LISTEN);

	for (i = 0; i < INCOMING_MAX; i++) {
		pfd[POLL_INCOMING + i].fd = -1;
		pfd[POLL_INCOMING + i].events = 0;
		incoming[i] = NULL;
	}

	return 0;
}

int iscsi_init(int *npfd)
{
	iscsi_nl_init();
	*npfd = POLL_MAX;

	return 0;
}
