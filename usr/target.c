/*
 * Target framework target daemon
 *
 * (C) 2005 FUJITA Tomonori <tomof@acm.org>
 * (C) 2005 Mike Christie <michaelc@cs.wisc.edu>
 * This code is licenced under the GPL.
 */

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <search.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <linux/fs.h>
#include <linux/netlink.h>
#include <scsi/scsi_tgt_if.h>

#include "tgtd.h"
#include "tgtadm.h"
#include "dl.h"
#include "tgt_sysfs.h"

#define	DEFAULT_NR_DEVICE	512
#define	MAX_NR_DEVICE		(1 << 20)

enum {
	POLL_IPC_CTRL,
	POLL_NL_CMD,
};

struct device {
	int fd;
	uint64_t addr; /* persistent mapped address */
	uint64_t size;
	int state;

	/* queue */
};

struct target {
	struct pollfd pfd[2];
	int tid;

	struct device **devt;
	uint64_t max_device;
};

static struct target *target;

static mode_t dmode = S_IRUSR|S_IWUSR|S_IXUSR|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH;
static mode_t fmode = S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH;

static void resize_device_table(struct target *target, uint64_t did)
{
	struct device *device;
	void *p, *q;

	p = calloc(did + 1, sizeof(device));
	memcpy(p, target->devt, sizeof(device) * target->max_device);
	q = target->devt;
	target->devt = p;
	target->max_device = did + 1;
	free(q);
}

static uint64_t try_mmap_device(int fd, uint64_t size)
{
	void *p;

	p = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (p == MAP_FAILED)
		return 0;
	else
		return (unsigned long) p;
}

int tgt_device_create(int tid, uint64_t did, int dfd)
{
	int err, fd;
	struct stat st;
	char path[PATH_MAX], buf[32];
	uint64_t size;
	struct device *device;

	if (did >= MAX_NR_DEVICE) {
		eprintf("Too big device id %" PRIu64 "%d\n",
			did, MAX_NR_DEVICE);
		return -EINVAL;
	}

	err = ioctl(dfd, BLKGETSIZE64, &size);
	if (err < 0) {
		eprintf("Cannot get size %d\n", dfd);
		return err;
	}

	snprintf(path, sizeof(path), TGT_TARGET_SYSFSDIR "/target%d", tid);
	err = stat(path, &st);
	if (err < 0) {
		eprintf("Cannot find target %d\n", tid);
		return err;
	}

	snprintf(path, sizeof(path), TGT_DEVICE_SYSFSDIR "/device%d:%" PRIu64,
		 tid, did);

	err = mkdir(path, dmode);
	if (err < 0) {
		eprintf("Cannot create %s\n", path);
		return err;
	}

	snprintf(path, sizeof(path), TGT_DEVICE_SYSFSDIR "/device%d:%" PRIu64 "/fd",
		 tid, did);
	fd = open(path, O_RDWR|O_CREAT|O_EXCL, fmode);
	if (fd < 0) {
		eprintf("Cannot create %s\n", path);
		return err;
	}
	snprintf(buf, sizeof(buf), "%d", dfd);
	err = write(fd, buf, strlen(buf));
	close(fd);
	if (err < 0) {
		eprintf("Cannot write %s\n", path);
		return err;
	}

	snprintf(path, sizeof(path), TGT_DEVICE_SYSFSDIR "/device%d:%" PRIu64 "/size",
		 tid, did);
	fd = open(path, O_RDWR|O_CREAT|O_EXCL, fmode);
	if (fd < 0) {
		eprintf("Cannot create %s\n", path);
		return err;
	}
	snprintf(buf, sizeof(buf), "%" PRIu64, size);
	err = write(fd, buf, strlen(buf));
	close(fd);
	if (err < 0) {
		eprintf("Cannot write %s\n", path);
		return err;
	}

	if (did >= target->max_device)
		resize_device_table(target, did);

	device = malloc(sizeof(*device));
	device->fd = dfd;
	device->state = 0;
	device->addr = try_mmap_device(dfd, size);
	device->size = size;
	target->devt[did] = device;

	if (device->addr)
		eprintf("Succeed to mmap the device %" PRIx64 "\n",
			device->addr);

	return 0;
}

int tgt_device_destroy(int tid, uint64_t did)
{
	char path[PATH_MAX];
	int err;
	struct device *device;

	if (target->max_device <= did)
		return -ENOENT;

	snprintf(path, sizeof(path), TGT_DEVICE_SYSFSDIR "/device%d:%" PRIu64 "/fd",
		 tid, did);
	err = unlink(path);
	if (err < 0) {
		eprintf("Cannot unlink %s\n", path);
		goto out;
	}

	snprintf(path, sizeof(path), TGT_DEVICE_SYSFSDIR "/device%d:%" PRIu64 "/size",
		 tid, did);
	err = unlink(path);
	if (err < 0) {
		eprintf("Cannot unlink %s\n", path);
		goto out;
	}

	snprintf(path, sizeof(path), TGT_DEVICE_SYSFSDIR "/device%d:%" PRIu64,
		 tid, did);
	err = rmdir(path);
	if (err < 0)
		eprintf("Cannot unlink %s\n", path);

	device = target->devt[did];
	target->devt[did] = NULL;
	if (device->addr)
		munmap((void *) (unsigned long) device->addr, device->size);

	free(device);
out:
	return err;
}

int tgt_device_init(void)
{
	int err;

	system("rm -rf " TGT_TARGET_SYSFSDIR);
	system("rm -rf " TGT_DEVICE_SYSFSDIR);

	err = mkdir(TGT_TARGET_SYSFSDIR, dmode);
	if (err < 0) {
		perror("Cannot create " TGT_TARGET_SYSFSDIR);
		return err;
	}

	err = mkdir(TGT_DEVICE_SYSFSDIR, dmode);
	if (err < 0)
		perror("Cannot create " TGT_DEVICE_SYSFSDIR);

	return err;
}

static void ipc_ctrl(int fd)
{
	struct iovec iov;
	struct msghdr msg;
	struct nlmsghdr *nlh;
	struct tgtadm_req *req;
	struct tgtadm_res *res;
	char rbuf[2048], buf[2048];
	int err;

	nlh = (struct nlmsghdr *) rbuf;
	iov.iov_base = nlh;
	iov.iov_len = NLMSG_ALIGN(sizeof(struct nlmsghdr));
	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	err = recvmsg(fd, &msg, MSG_PEEK);

	iov.iov_base = nlh;
	iov.iov_len = NLMSG_ALIGN(nlh->nlmsg_len);
	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	err = recvmsg(fd, &msg, MSG_DONTWAIT);

	req = NLMSG_DATA(nlh);
	dprintf("%d %d %d %d\n", req->mode, req->typeid, err, nlh->nlmsg_len);

	tgt_mgmt(rbuf, buf);

	nlh = (struct nlmsghdr *) buf;
	res = NLMSG_DATA(nlh);
	res->addr = req->addr;
	dprintf("%d %lx\n", nlh->nlmsg_len, res->addr);
	err = write(fd, nlh, nlh->nlmsg_len);
}


static int set_pdu_size(int fd)
{
	struct nlmsghdr *nlh;
	char buf[1024];
	int err;

peek_again:
	err = __nl_read(fd, buf, sizeof(buf), MSG_PEEK);
	if (err < 0) {
		if (errno == EAGAIN || errno == EINTR)
			goto peek_again;
		return err;
	}

	nlh = (struct nlmsghdr *) buf;

	dprintf("%d\n", nlh->nlmsg_len);

	return nlh->nlmsg_len;
}

/* FIXME */

#undef offsetof
#ifdef __compiler_offsetof
#define offsetof(TYPE,MEMBER) __compiler_offsetof(TYPE,MEMBER)
#else
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

#define LIST_HEAD_INIT(name) { &(name), &(name) }

#define INIT_LIST_HEAD(ptr) do { \
	(ptr)->q_forw = (ptr); (ptr)->q_back = (ptr); \
} while (0)

#define container_of(ptr, type, member) ({			\
        const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
        (type *)( (char *)__mptr - offsetof(type,member) );})

#define list_entry(ptr, type, member) \
	container_of(ptr, type, member)

#define list_for_each_entry(pos, head, member)				\
	for (pos = list_entry((head)->q_forw, typeof(*pos), member);	\
	     &pos->member != (head); 	\
	     pos = list_entry(pos->member.q_forw, typeof(*pos), member))

struct qelem {
	struct qelem *q_forw;
	struct qelem *q_back;
};

static struct qelem cqueue = LIST_HEAD_INIT(cqueue);

struct cmd {
	struct qelem clist;
	uint32_t cid;
	uint64_t devid;
	uint64_t uaddr;
	uint32_t len;
	int mmap;
};

static struct cmd *find_cmd(uint32_t cid)
{
	struct cmd *cmd;

	list_for_each_entry(cmd, &cqueue, clist) {
		if (cmd->cid == cid)
			return cmd;
	}
	return NULL;
}

#define	MAX_COMMAND_SIZE	16

static int cmd_queue(int fd, char *reqbuf)
{
	int result, len = 0;
	struct tgt_event *ev_req = (struct tgt_event *) reqbuf;
	char resbuf[NLMSG_SPACE(sizeof(struct tgt_event))];
	struct tgt_event *ev_res = NLMSG_DATA(resbuf);
	uint64_t offset, devid;
	uint32_t cid = ev_req->k.cmd_req.cid;
	uint8_t *pdu, rw = 0, try_map = 0;
	unsigned long uaddr = 0;
	int host_no = ev_req->k.cmd_req.host_no;
	struct cmd *cmd;

	memset(resbuf, 0, sizeof(resbuf));
	pdu = (uint8_t *) ev_req->data;

	devid = scsi_get_devid(pdu + MAX_COMMAND_SIZE);
	dprintf("%u %x %" PRIx64 "\n", cid, pdu[0], devid);

	if (target->max_device > devid && target->devt[devid])
		uaddr = target->devt[devid]->addr;

	/* FIXME */
	result = scsi_cmd_process(target->tid, pdu, &len,
				  ev_req->k.cmd_req.data_len,
				  &uaddr, &rw, &try_map, &offset, devid);

	dprintf("%u %x %lx %" PRIu64 " %d\n", cid, pdu[0], uaddr, offset, result);

	cmd = malloc(sizeof(*cmd));
	cmd->cid = cid;
	cmd->devid = devid;
	cmd->uaddr = uaddr;
	cmd->len = len;
	cmd->mmap = try_map;

	insque(&cmd->clist, &cqueue);

	ev_res->u.cmd_res.host_no = host_no;
	ev_res->u.cmd_res.cid = cid;
	ev_res->u.cmd_res.len = len;
	ev_res->u.cmd_res.result = result;
	ev_res->u.cmd_res.uaddr = uaddr;
	ev_res->u.cmd_res.rw = rw;
	ev_res->u.cmd_res.try_map = try_map;
	ev_res->u.cmd_res.offset = offset;

	return __nl_write(fd, TGT_UEVENT_CMD_RES, resbuf,
			  NLMSG_SPACE(sizeof(*ev_res)));
}

static void cmd_done(char *buf)
{
	struct tgt_event *ev = (struct tgt_event *) buf;
	int err = 0;
	uint32_t cid = ev->k.cmd_done.cid;
	struct cmd *cmd;
	int do_munmap;

	cmd = find_cmd(cid);
	if (!cmd) {
		eprintf("Cannot find cmd %u\n", cid);
		return;
	}
	remque(&cmd->clist);
	do_munmap = cmd->mmap;

	if (do_munmap) {
		if (cmd->devid >= target->max_device) {
			eprintf("%" PRIu64 " %" PRIu64 "\n",
				cmd->devid, target->max_device);
			exit(1);
		}

		if (target->devt[cmd->devid]) {
			if (target->devt[cmd->devid]->addr)
				do_munmap = 0;
		} else {
			eprintf("%" PRIu64 " is null\n", cmd->devid);
			exit(1);
		}
	}

	err = scsi_cmd_done(do_munmap, !cmd->mmap, cmd->uaddr, cmd->len);

	dprintf("%d %" PRIx64 " %u %d\n", cmd->mmap, cmd->uaddr, cmd->len, err);

	free(cmd);
}

static void nl_cmd(int fd)
{
	struct nlmsghdr *nlh;
	struct tgt_event *ev;
	static int pdu_size;
	char buf[1024];
	int err;

	if (!pdu_size)
		pdu_size = set_pdu_size(fd);

	err = __nl_read(fd, buf, pdu_size, MSG_WAITALL);

	nlh = (struct nlmsghdr *) buf;
	ev = (struct tgt_event *) NLMSG_DATA(nlh);

	if (nlh->nlmsg_len != pdu_size) {
		eprintf("unexpected len %d %d\n", nlh->nlmsg_len, pdu_size);
		exit(1);
	}

	switch (nlh->nlmsg_type) {
	case TGT_KEVENT_CMD_REQ:
		cmd_queue(fd, NLMSG_DATA(buf));
		break;
	case TGT_KEVENT_CMD_DONE:
		cmd_done(NLMSG_DATA(buf));
		break;
	default:
		eprintf("unknown event %u\n", nlh->nlmsg_type);
		exit(1);
	}

}

static int bind_nls(int fd)
{
	struct sockaddr_nl addr;

	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;
	addr.nl_pid = getpid();
	addr.nl_groups = 0;

	return bind(fd, (struct sockaddr *)&addr, sizeof(addr));
}

static void tthread_event_loop(struct target *target)
{
	struct pollfd *pfd = target->pfd;
	int fd, err;

	fd = nl_init();
	dprintf("%d\n", fd);
	err = bind_nls(fd);
	dprintf("%d\n", err);

	target->pfd[POLL_NL_CMD].fd = fd;
	target->pfd[POLL_NL_CMD].events = POLLIN;

	dprintf("Target thread started %u %d\n", getpid(), fd);

	while (1) {
		err = poll(pfd, 2, -1);
		dprintf("target thread event %d\n", err);

		if (err < 0) {
			if (errno != EINTR)
				exit(1);
			else
				continue;
		}

		if (pfd[POLL_IPC_CTRL].revents)
			ipc_ctrl(pfd[POLL_IPC_CTRL].fd);

		if (pfd[POLL_NL_CMD].revents)
			nl_cmd(pfd[POLL_NL_CMD].fd);
	}

	free(target);
}

static int target_dir_create(int tid, int pid)
{
	char path[PATH_MAX], buf[32];
	int err, fd;

	snprintf(path, sizeof(path), TGT_TARGET_SYSFSDIR "/target%d", tid);
	err = mkdir(path, dmode);
	if (err < 0) {
		eprintf("Cannot create %s\n", path);
		return err;
	}

	snprintf(path, sizeof(path), TGT_TARGET_SYSFSDIR "/target%d/pid", tid);
	fd = open(path, O_RDWR|O_CREAT|O_EXCL, fmode);
	if (fd < 0) {
		eprintf("Cannot create %s\n", path);
		return err;
	}
	snprintf(buf, sizeof(buf), "%d", pid);
	err = write(fd, buf, strlen(buf));
	close(fd);

	return 0;
}

int target_thread_create(int *sfd)
{
	pid_t pid;
	int fd[2];
	static int tid = 0;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fd) < 0) {
		eprintf("Cannot create socketpair %d\n", errno);
		return -1;
	}

	tid++;

	pid = fork();
	if (pid < 0)
		return -ENOMEM;
	else if (pid) {
		*sfd = fd[0];
		close(fd[1]);
		target_dir_create(tid, pid);
		return tid;
	}

	target = malloc(sizeof(*target));
	if (!target) {
		eprintf("Out of memoryn\n");
		exit(1);
	}

	target->devt = calloc(DEFAULT_NR_DEVICE, sizeof(struct device *));
	target->max_device = DEFAULT_NR_DEVICE;
	target->tid = tid;

	close(fd[0]);
	target->pfd[POLL_IPC_CTRL].fd = fd[1];
	target->pfd[POLL_IPC_CTRL].events = POLLIN;

	tthread_event_loop(target);

	return 0;
}
