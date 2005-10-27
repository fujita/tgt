/*
 * Core target framework user-space daemon
 *
 * (C) 2005 FUJITA Tomonori <tomof@acm.org>
 * (C) 2005 Mike Christie <michaelc@cs.wisc.edu>
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
#include <dirent.h>

#include <tgt_if.h>
#include "tgtd.h"
#include "dl.h"

#define	POLLS_PER_DRV	64

int nl_fd, ipc_fd;

enum {
	POLL_NL,
	POLL_IPC,
};

static struct option const long_options[] =
{
	{"foreground", no_argument, 0, 'f'},
	{"debug", required_argument, 0, 'd'},
	{"version", no_argument, 0, 'v'},
	{"help", no_argument, 0, 'h'},
	{0, 0, 0, 0},
};

static char program_name[] = "tgtd";

static void usage(int status)
{
	if (status != 0)
		fprintf(stderr, "Try `%s --help' for more information.\n", program_name);
	else {
		printf("Usage: %s [OPTION]\n", program_name);
		printf("\
Target framework daemon.\n\
  -f, --foreground        make the program run in the foreground\n\
  -d, --debug debuglevel  print debugging information\n\
  -h, --help              display this help and exit\n\
");
	}
	exit(1);
}

static void signal_catch(int signo) {
}

static void init(int daemon, int debug)
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
		fprintf(stderr, "can not adjust oom-killer's pardon %s\n", path);
		return;
	}
	write(fd, "-17\n", 4);
	close(fd);

	if (log_init(program_name, DEFAULT_AREA_SIZE, daemon, debug) < 0) {
		fprintf(stderr, "can not start the logger daemon\n");
		exit(-1);
	}
}

static void event_loop(int nr_dls, struct pollfd *poll_array)
{
	int err, i, poll_max = (nr_dls + 1) * POLLS_PER_DRV;
	void (* fn)(struct pollfd *, int);

	while (1) {
		if ((err = poll(poll_array, poll_max, -1)) < 0) {
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

		for (i = 0; i < nr_dls; i++) {
			fn = dl_poll_fn(i);
			if (fn)
				fn(poll_array + ((i + 1) * POLLS_PER_DRV), POLLS_PER_DRV);
		}
	}
}

static struct pollfd * poll_init(int nr)
{
	struct pollfd *array;
	void (* fn)(struct pollfd *, int);
	int i;

	array = calloc((nr + 1) * POLLS_PER_DRV,
		       sizeof(struct pollfd));
	if (!array)
		exit(-ENOMEM);

	array[POLL_NL].fd = nl_fd;
	array[POLL_NL].events = POLLIN;
	array[POLL_IPC].fd = ipc_fd;
	array[POLL_IPC].events = POLLIN;

	for (i = 0; i < nr; i++) {
		fn = dl_poll_init_fn(i);
		if (fn)
			fn(array + (i + 1) * POLLS_PER_DRV, POLLS_PER_DRV);
	}

	return array;
}

int main(int argc, char **argv)
{
	int ch, longindex;
	int is_daemon = 1, is_debug = 1;
	int nr;
	pid_t pid;
	struct pollfd *poll_array;

	while ((ch = getopt_long(argc, argv, "fd:vh", long_options, &longindex)) >= 0) {
		switch (ch) {
		case 'f':
			is_daemon = 0;
			break;
		case 'd':
			is_debug = atoi(optarg);
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

	init(is_daemon, is_debug);

	if (is_daemon) {
		pid = fork();
		if (pid < 0)
			exit(-1);
		else if (pid)
			exit(0);

		chdir("/");

		close(0);
		open("/dev/null", O_RDWR);
		dup2(0, 1);
		dup2(0, 2);
		setsid();
	}

	nl_fd = nl_open(&nr);
	if (nl_fd < 0)
		exit(nl_fd);

	ipc_fd = ipc_open();
	if (ipc_fd < 0)
		exit(ipc_fd);

	poll_array = poll_init(nr);

	dl_config_load();

	event_loop(nr, poll_array);

	return 0;
}
