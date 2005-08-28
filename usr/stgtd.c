/*
 * SCSI target framework user-space daemon
 *
 * (C) 2005 FUJITA Tomonori <tomof@acm.org>
 *
 * This code is licenced under the GPL.
 */

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <signal.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <asm/types.h>
#include <sys/poll.h>
#include <sys/signal.h>
#include <sys/stat.h>

#include <stgt_if.h>
#include "stgtd.h"

int nl_fd, ipc_fd;
uint32_t stgtd_debug = 1;

enum {
	POLL_NL,
	POLL_IPC,
	POLL_MAX,
};

static struct option const long_options[] =
{
	{"foreground", no_argument, 0, 'f'},
	{"debug", required_argument, 0, 'd'},
	{"version", no_argument, 0, 'v'},
	{"help", no_argument, 0, 'h'},
	{0, 0, 0, 0},
};

static char program_name[] = "stgtd";

static void usage(int status)
{
	if (status != 0)
		fprintf(stderr, "Try `%s --help' for more information.\n", program_name);
	else {
		printf("Usage: %s [OPTION]\n", program_name);
		printf("\
SCSI target daemon.\n\
  -f, --foreground        make the program run in the foreground\n\
  -d, --debug debuglevel  print debugging information\n\
  -h, --help              display this help and exit\n\
");
	}
	exit(1);
}

static void signal_catch(int signo) {
}

static void init(void)
{
	int fd;
	char path[64];
	struct sigaction sa_old;
	struct sigaction sa_new;

	/* do not allow ctrl-c for now... */
	sa_new.sa_handler = signal_catch;
	sigemptyset(&sa_new.sa_mask);
	sa_new.sa_flags = 0;
	sigaction(SIGINT, &sa_new, &sa_old );
	sigaction(SIGPIPE, &sa_new, &sa_old );
	sigaction(SIGTERM, &sa_new, &sa_old );

	/* Should we use RT stuff? */
	nice(-20);

	/* Avoid oom-killer */
	sprintf(path, "/proc/%d/oom_adj", getpid());
	fd = open(path, O_WRONLY);
	if (fd < 0) {
		eprintf("can not adjust oom-killer's pardon %s\n", path);
		return;
	}
	write(fd, "-17\n", 4);
	close(fd);
}

static void event_loop(struct pollfd *poll_array)
{
	int err;

	while (1) {
		if ((err = poll(poll_array, POLL_MAX, -1)) < 0) {
			if (errno != EINTR) {
				eprintf("%d %d\n", err, errno);
				exit(1);
			}
			continue;
		}

		if (poll_array[POLL_NL].revents)
			nl_event_handle(nl_fd);

		if (poll_array[POLL_IPC].revents)
			ipc_event_handle(ipc_fd);
	}
}

int main(int argc, char **argv)
{
	int ch, longindex;
	struct pollfd poll_array[POLL_MAX + 1];

	while ((ch = getopt_long(argc, argv, "fd:vh", long_options, &longindex)) >= 0) {
		switch (ch) {
		case 'f':
			break;
		case 'd':
			stgtd_debug = atoi(optarg);
			break;
		case 'v':
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

	init();

	memset(poll_array, 0, sizeof(poll_array));

	nl_fd = nl_open();
	if (nl_fd < 0)
		exit(nl_fd);

	ipc_fd = ipc_open();
	if (ipc_fd < 0)
		exit(ipc_fd);

	poll_array[POLL_NL].fd = nl_fd;
	poll_array[POLL_NL].events = POLLIN;
	poll_array[POLL_IPC].fd = ipc_fd;
	poll_array[POLL_IPC].events = POLLIN;

	event_loop(poll_array);

	return 0;
}
