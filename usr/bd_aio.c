#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

#include <linux/fs.h>

#include "list.h"
#include "util.h"
#include "tgtd.h"
#include "libaio.h"

/*
 * We need an interface to wait for both synchronous and asynchronous
 * descriptors (something like BSD's kqueue). Now we use a kernel
 * patch to return an fd associated with the AIO context because Xen
 * blktap uses it (so we avoid introducing another patch). However,
 * I'm not sure the patch will go into mainline. Another approach,
 * IO_CMD_EPOLL_WAIT, looks more promising. kqueue is promising too.
 */

#define REQUEST_ASYNC_FD 1

/* FIXME */
#define MAX_AIO_REQS 1024
#define O_DIRECT 040000 /* who defines this?*/

struct bd_aio_info {
	int fd;
	int aio_fd;

	io_context_t ctx;
	/* TODO: batch requests*/
	struct iocb iocb[MAX_AIO_REQS];
	struct io_event events[MAX_AIO_REQS];
};

static void aio_event_handler(int fd, void *data)
{
	struct tgt_device *dev = (struct tgt_device *) data;
	struct bd_aio_info *bai = (struct bd_aio_info *) dev->bddata;
	int i, nr;
	struct iocb *iocb;

	nr = io_getevents(bai->ctx, 0, MAX_AIO_REQS, bai->events, NULL);

	for (i = 0; i < nr; i++) {
		iocb = bai->events[i].obj;
		target_cmd_io_done(iocb->data, 0);
	}
}

static struct tgt_device *bd_aio_open(char *path, int *fd, uint64_t *size)
{
	struct tgt_device *dev;
	struct bd_aio_info *bai;
	int err;

	dev = malloc(sizeof(*dev) + sizeof(struct bd_aio_info));
	if (!dev)
		return NULL;

	*fd = backed_file_open(path, O_RDWR| O_LARGEFILE | O_DIRECT, size);
	if (*fd < 0)
		goto free_info;

	bai = (struct bd_aio_info *)dev->bddata;

	bai->ctx = (io_context_t) REQUEST_ASYNC_FD;
	bai->aio_fd = io_setup(MAX_AIO_REQS, &bai->ctx);
	if (bai->aio_fd < 0)
		goto close_fd;

	err = tgt_event_add(bai->aio_fd, POLL_IN, aio_event_handler, dev);
	if (err)
		goto aio_cb_destroy;

	bai->fd = *fd;
	return dev;

aio_cb_destroy:
	io_destroy(bai->ctx);
close_fd:
	close(*fd);
free_info:
	free(dev);

	return NULL;
}

static void bd_aio_close(struct tgt_device *dev)
{
	struct bd_aio_info *bai = (struct bd_aio_info *) dev->bddata;

	tgt_event_del(bai->fd);
	io_destroy(bai->ctx);
	free(dev);
}

static int bd_aio_cmd_submit(struct tgt_device *dev, int rw, uint32_t datalen,
			     unsigned long *uaddr,
			     uint64_t offset, int *async, void *key)
{
	struct bd_aio_info *bai = (struct bd_aio_info *) dev->bddata;
	struct iocb iocb, *io;

	*async = 1;

	io = &iocb;
	memset(io, 0, sizeof(*io));

	io->data = key;
	if (rw == READ)
		io_prep_pread(io, bai->fd, uaddr, datalen, offset);
	else
		io_prep_pwrite(io, bai->fd, uaddr, datalen, offset);

	return io_submit(bai->ctx, 1, &io);
}

static int bd_aio_cmd_done(int do_munmap, int do_free, uint64_t uaddr, int len)
{
	return 0;
}

struct backedio_template aio_bdt = {
	.bd_open	= bd_aio_open,
	.bd_close	= bd_aio_close,
	.bd_cmd_submit	= bd_aio_cmd_submit,
	.bd_cmd_done	= bd_aio_cmd_done,
};
