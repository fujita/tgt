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
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <linux/fs.h>
#include <linux/netlink.h>

#include <tgt_if.h>
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

	system("rm -rf " TGT_DEVICE_SYSFSDIR);

	err = mkdir(TGT_DEVICE_SYSFSDIR, dmode);
	if (err < 0)
		perror("Cannot create" TGT_DEVICE_SYSFSDIR);

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

static int cmd_queue(struct driver_info *dinfo, int fd, char *reqbuf)
{
	int result, len = 0;
	struct tgt_event *ev_req = (struct tgt_event *) reqbuf;
	char resbuf[NLMSG_SPACE(sizeof(struct tgt_event))];
	struct tgt_event *ev_res = NLMSG_DATA(resbuf);
	uint64_t offset, cid = ev_req->k.cmd_req.cid, devid;
	uint8_t *pdu, rw = 0, try_map = 0;
	unsigned long uaddr = 0;
	static int (*fn) (int, uint8_t *, int *, uint32_t,
			  unsigned long *, uint8_t *, uint8_t *, uint64_t *, uint64_t);
	static uint64_t (*get_devid) (uint8_t *pdu);
	int tid = ev_req->k.cmd_req.tid;
	int typeid = ev_req->k.cmd_req.typeid;

	memset(resbuf, 0, sizeof(resbuf));
	pdu = (uint8_t *) ev_req->data;
	dprintf("%" PRIu64 " %x\n", cid, pdu[0]);

	if (!get_devid)
		get_devid = dl_proto_get_devid(dinfo, tid, typeid);

	if (get_devid)
		devid = get_devid(pdu);
	else {
		eprintf("Cannot find get_devid\n");
		devid = TGT_INVALID_DEV_ID;
	}

	if (target->max_device > devid && target->devt[devid])
		uaddr = target->devt[devid]->addr;

	if (!fn)
		fn = dl_proto_cmd_process(dinfo, tid, typeid);
	if (fn)
		result = fn(tid,
			    pdu,
			    &len,
			    ev_req->k.cmd_req.data_len,
			    &uaddr, &rw, &try_map, &offset, devid);
	else {
		result = -EINVAL;
		eprintf("Cannot process cmd %d %" PRIu64 "\n",
			tid, cid);
	}

	ev_res->u.cmd_res.tid = tid;
	ev_res->u.cmd_res.cid = cid;
	ev_res->u.cmd_res.devid = devid;
	ev_res->u.cmd_res.len = len;
	ev_res->u.cmd_res.result = result;
	ev_res->u.cmd_res.uaddr = uaddr;
	ev_res->u.cmd_res.rw = rw;
	ev_res->u.cmd_res.try_map = try_map;
	ev_res->u.cmd_res.offset = offset;

	log_debug("scsi_cmd_process res %d len %d\n", result, len);

	return __nl_write(fd, TGT_UEVENT_CMD_RES, resbuf,
			  NLMSG_SPACE(sizeof(*ev_res)));
}

static void cmd_done(struct driver_info *dinfo, char *buf)
{
	static int (*done) (int do_munmap, int do_free, uint64_t uaddr, int len);
	struct tgt_event *ev = (struct tgt_event *) buf;
	int err = 0;
	int do_munmap = ev->k.cmd_done.mmapped;

	if (!done)
		done = dl_cmd_done_fn(dinfo, ev->k.cmd_done.typeid);

	if (done) {
		if (do_munmap) {
			uint64_t devid = ev->k.cmd_done.devid;

			if (devid >= target->max_device) {
				eprintf("%" PRIu64 " %" PRIu64 "\n",
					devid, target->max_device);
				exit(1);
			}

			if (target->devt[devid]) {
				if (target->devt[devid]->addr)
					do_munmap = 0;
			} else {
				eprintf("%" PRIu64 " is null\n", devid);
				exit(1);
			}
		}
		err = done(do_munmap, !ev->k.cmd_done.mmapped,
			 ev->k.cmd_done.uaddr, ev->k.cmd_done.len);
	} else
		eprintf("Cannot handle cmd done\n");

	dprintf("%d %lx %u %d\n", ev->k.cmd_done.mmapped,
		ev->k.cmd_done.uaddr, ev->k.cmd_done.len, err);
}

static void nl_cmd(struct driver_info *dinfo, int fd)
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
		cmd_queue(dinfo, fd, NLMSG_DATA(buf));
		break;
	case TGT_KEVENT_CMD_DONE:
		cmd_done(dinfo, NLMSG_DATA(buf));
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
	struct driver_info d[MAX_DL_HANDLES];
	struct pollfd *pfd = target->pfd;
	int fd, err;

	fd = nl_init();
	dprintf("%d\n", fd);
	err = bind_nls(fd);
	dprintf("%d\n", err);

	target->pfd[POLL_NL_CMD].fd = fd;
	target->pfd[POLL_NL_CMD].events = POLLIN;

	err = dl_init(d);
	dprintf("%d\n", err);

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
			nl_cmd(d, pfd[POLL_NL_CMD].fd);
	}

	free(target);
}

int target_thread_create(int *sfd)
{
	pid_t pid;
	int fd[2];

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fd) < 0) {
		eprintf("Cannot create socketpair %d\n", errno);
		return -1;
	}

	pid = fork();
	if (pid < 0)
		return -ENOMEM;
	else if (pid) {
		*sfd = fd[0];
		close(fd[1]);
		return pid;
	}

	target = malloc(sizeof(*target));
	if (!target) {
		eprintf("Out of memoryn\n");
		exit(1);
	}

	target->devt = calloc(DEFAULT_NR_DEVICE, sizeof(struct device *));
	target->max_device = DEFAULT_NR_DEVICE;

	close(fd[0]);
	target->pfd[POLL_IPC_CTRL].fd = fd[1];
	target->pfd[POLL_IPC_CTRL].events = POLLIN;

	tthread_event_loop(target);

	return 0;
}
