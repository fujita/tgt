/*
 * Copyright (C) 2002-2003 Ardis Technolgies <roman@ardistech.com>
 *
 * Released under the terms of the GNU GPL v2.0.
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
#include "ietadm.h"

#define LISTEN_MAX		8
#define INCOMING_MAX		32

enum {
	POLL_LISTEN,
	POLL_IPC = POLL_LISTEN + LISTEN_MAX,
	POLL_NL,
	POLL_INCOMING,
	POLL_MAX = POLL_INCOMING + INCOMING_MAX,
};

static struct pollfd poll_array[POLL_MAX];
static struct connection *incoming[INCOMING_MAX];
static int incoming_cnt;
int ctrl_fd, ipc_fd, nl_fd;

static char program_name[] = "iscsid";

static struct option const long_options[] =
{
	{"config", required_argument, 0, 'c'},
	{"foreground", no_argument, 0, 'f'},
	{"debug", required_argument, 0, 'd'},
	{"isns", required_argument, 0, 's'},
	{"uid", required_argument, 0, 'u'},
	{"gid", required_argument, 0, 'g'},
	{"version", no_argument, 0, 'v'},
	{"help", no_argument, 0, 'h'},
	{0, 0, 0, 0},
};

/* This will be comfigurable by command line options */
extern struct config_operations plain_ops;
struct config_operations *cops = &plain_ops;

static void usage(int status)
{
	if (status != 0)
		fprintf(stderr, "Try `%s --help' for more information.\n", program_name);
	else {
		printf("Usage: %s [OPTION]\n", program_name);
		printf("\
iSCSI target daemon.\n\
  -c, --config=[path]     Execute in the config file.\n");
		printf("\
  -f, --foreground        make the program run in the foreground\n\
  -d, --debug debuglevel  print debugging information\n\
  -s, --isns=[ip]         work with isns server, default is disabled\n\
  -u, --uid=uid           run as uid, default is current user\n\
  -g, --gid=gid           run as gid, default is current user group\n\
  -h, --help              display this help and exit\n\
");
	}
	exit(1);
}

static void set_non_blocking(int fd)
{
	int res = fcntl(fd, F_GETFL);

	if (res != -1) {
		res = fcntl(fd, F_SETFL, res | O_NONBLOCK);
		if (res)
			log_warning("unable to set fd flags (%s)!", strerror(errno));
	} else
		log_warning("unable to get fd flags (%s)!", strerror(errno));
}

static void create_listen_socket(struct pollfd *array)
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
		log_error("unable to get address info (%s)!", strerror(errno));
		exit(1);
	}

	for (i = 0, res = res0; res && i < LISTEN_MAX; i++, res = res->ai_next) {
		sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (sock < 0) {
			log_error("unable to create server socket (%s) %d %d %d!",
				  strerror(errno), res->ai_family,
				  res->ai_socktype, res->ai_protocol);
			continue;
		}

		opt = 1;
		if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)))
			log_warning("unable to set SO_REUSEADDR on server socket (%s)!",
				    strerror(errno));
		opt = 1;
		if (res->ai_family == AF_INET6 &&
		    setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt)))
			continue;

		if (bind(sock, res->ai_addr, res->ai_addrlen)) {
			log_error("unable to bind server socket (%s)!", strerror(errno));
			continue;
		}

		if (listen(sock, INCOMING_MAX)) {
			log_error("unable to listen to server socket (%s)!", strerror(errno));
			continue;
		}

		set_non_blocking(sock);

		array[i].fd = sock;
		array[i].events = POLLIN;
	}

	freeaddrinfo(res0);
}

static void accept_connection(int listen)
{
	struct sockaddr_storage from;
	socklen_t namesize;
	struct pollfd *pollfd;
	struct connection *conn;
	int fd, i;

	namesize = sizeof(from);
	if ((fd = accept(listen, (struct sockaddr *) &from, &namesize)) < 0) {
		if (errno != EINTR && errno != EAGAIN) {
			perror("accept(incoming_socket)");
			exit(1);
		}
		return;
	}

	for (i = 0; i < INCOMING_MAX; i++) {
		if (!incoming[i])
			break;
	}
	if (i >= INCOMING_MAX) {
		log_error("unable to find incoming slot? %d\n", i);
		exit(1);
	}

	if (!(conn = conn_alloc())) {
		log_error("fail to allocate %s", "conn\n");
		exit(1);
	}
	conn->fd = fd;
	incoming[i] = conn;
	conn_read_pdu(conn);

	set_non_blocking(fd);
	pollfd = &poll_array[POLL_INCOMING + i];
	pollfd->fd = fd;
	pollfd->events = POLLIN;
	pollfd->revents = 0;

	incoming_cnt++;
	if (incoming_cnt >= INCOMING_MAX)
		poll_array[POLL_LISTEN].events = 0;
}

void event_loop(void)
{
	int res, i, opt;
	struct connection *conn;
	struct pollfd *pollfd;

	create_listen_socket(poll_array + POLL_LISTEN);

	poll_array[POLL_IPC].fd = ipc_fd;
	poll_array[POLL_IPC].events = POLLIN;
	poll_array[POLL_NL].fd = nl_fd;
	poll_array[POLL_NL].events = POLLIN;

	for (i = 0; i < INCOMING_MAX; i++) {
		poll_array[POLL_INCOMING + i].fd = -1;
		poll_array[POLL_INCOMING + i].events = 0;
		incoming[i] = NULL;
	}

	while (1) {
		res = poll(poll_array, POLL_MAX, -1);
		if (res <= 0) {
			if (res < 0 && errno != EINTR) {
				perror("poll()");
				exit(1);
			}
			continue;
		}

		for (i = 0; i < LISTEN_MAX; i++) {
			if (poll_array[POLL_LISTEN + i].revents
			    && incoming_cnt < INCOMING_MAX)
				accept_connection(poll_array[POLL_LISTEN + i].fd);
		}

		if (poll_array[POLL_NL].revents)
			handle_iscsi_events(nl_fd);

		if (poll_array[POLL_IPC].revents)
			ietadm_request_handle(ipc_fd);

		for (i = 0; i < INCOMING_MAX; i++) {
			conn = incoming[i];
			pollfd = &poll_array[POLL_INCOMING + i];
			if (!conn || !pollfd->revents)
				continue;

			pollfd->revents = 0;

			switch (conn->iostate) {
			case IOSTATE_READ_BHS:
			case IOSTATE_READ_AHS_DATA:
			read_again:
				res = read(pollfd->fd, conn->buffer, conn->rwsize);
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
					pollfd->events = POLLOUT;

					log_pdu(2, &conn->req);
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
				setsockopt(pollfd->fd, SOL_TCP, TCP_CORK, &opt, sizeof(opt));
				res = write(pollfd->fd, conn->buffer, conn->rwsize);
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
								*((u8 *)conn->buffer + conn->rwsize++) = 0;
						}
						goto write_again;
					}
				case IOSTATE_WRITE_DATA:
					opt = 0;
					setsockopt(pollfd->fd, SOL_TCP, TCP_CORK, &opt, sizeof(opt));
					cmnd_finish(conn);

					switch (conn->state) {
					case STATE_KERNEL:
						conn_take_fd(conn, pollfd->fd);
						conn->state = STATE_CLOSE;
						break;
					case STATE_EXIT:
					case STATE_CLOSE:
						break;
					default:
						conn_read_pdu(conn);
						pollfd->events = POLLIN;
						break;
					}
					break;
				}

				break;
			default:
				log_error("illegal iostate %d for port %d!\n", conn->iostate, i);
				exit(1);
			}

			if (conn->state == STATE_CLOSE) {
				log_debug(0, "connection closed");
				conn_free_pdu(conn);
				conn_free(conn);
				close(pollfd->fd);
				pollfd->fd = -1;
				incoming[i] = NULL;
				incoming_cnt--;
			}
		}
	}
}

int main(int argc, char **argv)
{
	int ch, longindex;
	char *config = NULL;
	char isns_ip[32];
	uid_t uid = 0;
	gid_t gid = 0;

	while ((ch = getopt_long(argc, argv, "c:fd:s:u:g:vh", long_options, &longindex)) >= 0) {
		switch (ch) {
		case 'c':
			config = optarg;
			break;
		case 'f':
			log_daemon = 0;
			break;
		case 'd':
			log_level = atoi(optarg);
			break;
		case 's':
			memset(isns_ip, 0, sizeof(isns_ip));
			strncpy(isns_ip, optarg, sizeof(isns_ip));
			use_isns = 1;
			break;
		case 'u':
			uid = strtoul(optarg, NULL, 10);
			break;
		case 'g':
			gid = strtoul(optarg, NULL, 10);
			break;
		case 'v':
			printf("%s version %s\n", program_name, IET_VERSION_STRING);
			exit(0);
			break;
		case 'h':
			usage(0);
			break;
		default:
			usage(1);
			break;
		}
	}

	if ((nl_fd = nl_open()) < 0) {
		perror("netlink fd\n");
		exit(-1);
	};

	if ((ctrl_fd = ki->ctldev_open()) < 0) {
		perror("ctldev fd\n");
		exit(-1);
	}

	if ((ipc_fd = ietadm_request_listen()) < 0) {
		perror("ipc fd\n");
		exit(-1);
	}

	log_init();
	if (log_daemon) {
		char buf[64];
		pid_t pid;
		int fd;

		fd = open("/var/run/iscsi_trgt.pid", O_WRONLY|O_CREAT, 0644);
		if (fd < 0) {
			log_error("unable to create pid file");
			exit(1);
		}
		pid = fork();
		if (pid < 0) {
			log_error("starting daemon failed");
			exit(1);
		} else if (pid)
			exit(0);

		chdir("/");
		if (lockf(fd, F_TLOCK, 0) < 0) {
			log_error("unable to lock pid file");
			exit(1);
		}
		ftruncate(fd, 0);
		sprintf(buf, "%d\n", getpid());
		write(fd, buf, strlen(buf));

		close(0);
		open("/dev/null", O_RDWR);
		dup2(0, 1);
		dup2(0, 2);
		setsid();
	}

	if (use_isns) {
		if (initialize_iet_isns(isns_ip,
					ISCSI_LISTEN_PORT) < 0)
			use_isns = 0;
	}

	cops->init(config);

	if (uid && setuid(uid) < 0)
		perror("setuid\n");

	if (gid && setgid(gid) < 0)
		perror("setgid\n");

	event_loop();

	if (use_isns) {
		cleanup_iet_isns();
	}

	return 0;
}
