/*
 * SCSI target management functions
 *
 * Copyright (C) 2005-2007 FUJITA Tomonori <tomof@acm.org>
 * Copyright (C) 2005-2007 Mike Christie <michaelc@cs.wisc.edu>
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
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>

#include "list.h"
#include "tgtd.h"
#include "log.h"
#include "tgtadm.h"
#include "driver.h"
#include "util.h"

enum mgmt_task_state {
	MTASK_STATE_HDR_RECV,
	MTASK_STATE_PDU_RECV,
	MTASK_STATE_RSP_SEND,
};

struct mgmt_task {
	enum mgmt_task_state mtask_state;
	int retry;
	int done;
	char *buf;
	int bsize;
	struct tgtadm_req req;
	struct tgtadm_rsp rsp;
/* 	struct tgt_work work; */
};

static int ipc_fd;
char mgmt_path[256];

static void set_show_results(struct tgtadm_rsp *rsp, int *err)
{
	if (*err < 0)
		rsp->err = -*err;
	else {
		rsp->err = 0;
		rsp->len = *err + sizeof(*rsp);
		*err = 0;
	}
}

static int target_mgmt(int lld_no, struct mgmt_task *mtask)
{
	struct tgtadm_req *req = &mtask->req;
	struct tgtadm_rsp *rsp = &mtask->rsp;
	int err = TGTADM_INVALID_REQUEST;

	switch (req->op) {
	case OP_NEW:
		err = tgt_target_create(lld_no, req->tid, mtask->buf);
		break;
	case OP_DELETE:
		err = tgt_target_destroy(lld_no, req->tid, req->force);
		break;
	case OP_BIND:
		/* FIXME */
		if (req->len == sizeof(*req))
			err = tgt_bind_host_to_target(req->tid, req->host_no);
		else {
			char *p;

			p = strstr(mtask->buf, "initiator-address=");
			if (p)
				err = acl_add(req->tid, p + strlen("initiator-address="));

			p = strstr(mtask->buf, "initiator-name=");
			if (p)
				err = iqn_acl_add(req->tid, p + strlen("initiator-name="));
		}
		break;
	case OP_UNBIND:
		if (req->len == sizeof(*req))
			err = tgt_unbind_host_to_target(req->tid, req->host_no);
		else {
			char *p;

			p = strstr(mtask->buf, "initiator-address=");
			if (p) {
				err = acl_del(req->tid, p + strlen("initiator-address="));
			}

			p = strstr(mtask->buf, "initiator-name=");
			if (p) {
				err = iqn_acl_del(req->tid, p + strlen("initiator-name="));
			}
		}
		break;
	case OP_UPDATE:
	{
		char *p;
		err = TGTADM_UNSUPPORTED_OPERATION;

		p = strchr(mtask->buf, '=');
		if (!p)
			break;
		*p++ = '\0';

		if (!strcmp(mtask->buf, "state"))
			err = tgt_set_target_state(req->tid, p);
		else if (tgt_drivers[lld_no]->update)
			err = tgt_drivers[lld_no]->update(req->mode, req->op, req->tid,
							  req->sid, req->lun,
							  req->cid, mtask->buf);
		break;
	}
	case OP_SHOW:
		if (req->tid < 0) {
			retry:
			err = tgt_target_show_all(mtask->buf, mtask->bsize);
			if (err == mtask->bsize) {
				char *p;
				mtask->bsize <<= 1;
				p = realloc(mtask->buf, mtask->bsize);
				if (p) {
					mtask->buf = p;
					goto retry;
				} else {
					eprintf("out of memory\n");
					err = TGTADM_NOMEM;
				}
			}
		} else if (tgt_drivers[lld_no]->show)
			err = tgt_drivers[lld_no]->show(req->mode,
							req->tid,
							req->sid,
							req->cid, req->lun,
							mtask->buf, mtask->bsize);
		break;
	default:
		break;
	}

	if (req->op == OP_SHOW)
		set_show_results(rsp, &err);
	else {
		rsp->err = err;
		rsp->len = sizeof(*rsp);
	}
	return err;
}

static int portal_mgmt(int lld_no, struct mgmt_task *mtask,
		       struct tgtadm_req *req,
		       struct tgtadm_rsp *rsp)
{
	int err = TGTADM_INVALID_REQUEST;

	switch (req->op) {
	case OP_SHOW:
		if (tgt_drivers[lld_no]->show) {
			err = tgt_drivers[lld_no]->show(req->mode,
							req->tid, req->sid,
							req->cid, req->lun,
							mtask->buf,
							mtask->bsize);

			set_show_results(rsp, &err);
			return err;
		}
		break;
	case OP_NEW:
		err = tgt_portal_create(lld_no, mtask->buf);
		break;
	case OP_DELETE:
		err = tgt_portal_destroy(lld_no, mtask->buf);
		break;
	default:
		break;
	}

	rsp->err = err;
	rsp->len = sizeof(*rsp);

	return err;
}

static int device_mgmt(int lld_no, struct tgtadm_req *req, char *params,
		       struct tgtadm_rsp *rsp, int *rlen)
{
	int err = TGTADM_UNSUPPORTED_OPERATION;

	switch (req->op) {
	case OP_NEW:
		err = tgt_device_create(req->tid, req->device_type, req->lun,
					params, 1);
		break;
	case OP_DELETE:
		err = tgt_device_destroy(req->tid, req->lun, 0);
		break;
	case OP_UPDATE:
		err = tgt_device_update(req->tid, req->lun, params);
		break;
	default:
		break;
	}

	rsp->err = err;
	rsp->len = sizeof(*rsp);

	return err;
}

static int account_mgmt(int lld_no,  struct mgmt_task *mtask)
{
	struct tgtadm_req *req = &mtask->req;
	struct tgtadm_rsp *rsp = &mtask->rsp;
	int err = TGTADM_UNSUPPORTED_OPERATION;
	char *user, *password;

	switch (req->op) {
	case OP_NEW:
	case OP_DELETE:
	case OP_BIND:
	case OP_UNBIND:
		user = strstr(mtask->buf, "user=");
		if (!user)
			goto out;
		user += 5;

		if (req->op == OP_NEW) {
			password = strchr(user, ',');
			if (!password)
				goto out;

			*password++ = '\0';
			password += strlen("password=");

			err = account_add(user, password);
		} else {
			if (req->op == OP_DELETE) {
				err = account_del(user);
			} else
				err = account_ctl(req->tid, req->ac_dir,
						  user, req->op == OP_BIND);
		}
		break;
	case OP_SHOW:
	retry:
		err = account_show(mtask->buf, mtask->bsize);
		if (err == mtask->bsize) {
			char *p;
			mtask->bsize <<= 1;
			p = realloc(mtask->buf, mtask->bsize);
			if (p) {
				mtask->buf = p;
				goto retry;
			} else
				err = TGTADM_NOMEM;
		}
		break;
	default:
		break;
	}
out:
	if (req->op == OP_SHOW)
		set_show_results(rsp, &err);
	else {
		rsp->err = err;
		rsp->len = sizeof(*rsp);
	}
	return err;
}

static int sys_mgmt(int lld_no, struct mgmt_task *mtask)
{
	struct tgtadm_req *req = &mtask->req;
	struct tgtadm_rsp *rsp = &mtask->rsp;
	int err = TGTADM_INVALID_REQUEST, len = mtask->bsize;

	switch (req->op) {
	case OP_UPDATE:
		if (!strncmp(mtask->buf, "debug=", 6)) {
			if (!strncmp(mtask->buf+6, "on", 2)) {
				is_debug = 1;
				err = 0;
			} else if (!strncmp(mtask->buf+6, "off", 3)) {
				is_debug = 0;
				err = 0;
			}
			if (!err)
				eprintf("set debug to: %d\n", is_debug);
		} else if (tgt_drivers[lld_no]->update)
			err = tgt_drivers[lld_no]->update(req->mode, req->op,
							  req->tid,
							  req->sid, req->lun,
							  req->cid, mtask->buf);

		rsp->err = err;
		rsp->len = sizeof(*rsp);
		break;
	case OP_SHOW:
		err = system_show(req->mode, mtask->buf, len);
		if (err >= 0 && tgt_drivers[lld_no]->show) {
			err += tgt_drivers[lld_no]->show(req->mode,
							 req->tid, req->sid,
							 req->cid, req->lun,
							 mtask->buf + err, len - err);
		}
		set_show_results(rsp, &err);
		break;
	case OP_DELETE:
		if (is_system_inactive())
			err = 0;

		rsp->err = err;
		rsp->len = sizeof(*rsp);
		break;
	default:
		break;
	}

	return err;
}

static int connection_mgmt(int lld_no, struct mgmt_task *mtask,
			   struct tgtadm_req *req,
			   struct tgtadm_rsp *rsp)
{
	int err = TGTADM_INVALID_REQUEST;

	switch (req->op) {
	case OP_SHOW:
		if (tgt_drivers[lld_no]->show) {
			err = tgt_drivers[lld_no]->show(req->mode,
							req->tid, req->sid,
							req->cid, req->lun,
							mtask->buf,
							mtask->bsize);
			set_show_results(rsp, &err);
			return err;
		}
		break;
	default:
		if (tgt_drivers[lld_no]->update)
			err = tgt_drivers[lld_no]->update(req->mode, req->op,
							  req->tid,
							  req->sid, req->lun,
							  req->cid, mtask->buf);
		rsp->err = err;
		rsp->len = sizeof(*rsp);
		break;
	}

	return err;
}

static int tgt_mgmt(struct mgmt_task *mtask)
{
	struct tgtadm_req *req = &mtask->req;
	struct tgtadm_rsp *rsp = &mtask->rsp;
	int lld_no, err = TGTADM_INVALID_REQUEST, len = mtask->bsize;

	if (!strlen(req->lld))
		lld_no = 0;
	else {
		lld_no = get_driver_index(req->lld);
		if (lld_no < 0 || tgt_drivers[lld_no]->drv_state != DRIVER_INIT) {
			if (lld_no < 0)
				eprintf("can't find the driver %s\n", req->lld);
			else
				eprintf("driver %s is in state: %s\n",
					req->lld, driver_state_name(tgt_drivers[lld_no]));
			rsp->err = TGTADM_NO_DRIVER;
			rsp->len = sizeof(*rsp);
			return 0;
		}
	}

	dprintf("%d %d %d %d %d %" PRIx64 " %" PRIx64 " %s %d\n",
		req->len, lld_no, req->mode, req->op,
		req->tid, req->sid, req->lun, mtask->buf, getpid());

	switch (req->mode) {
	case MODE_SYSTEM:
		err = sys_mgmt(lld_no, mtask);
		break;
	case MODE_TARGET:
		err = target_mgmt(lld_no, mtask);
		break;
	case MODE_PORTAL:
		err = portal_mgmt(lld_no, mtask, req, rsp);
		break;
	case MODE_DEVICE:
		err = device_mgmt(lld_no, req, mtask->buf, rsp, &len);
		break;
	case MODE_ACCOUNT:
		err = account_mgmt(lld_no, mtask);
		break;
	case MODE_CONNECTION:
		err = connection_mgmt(lld_no, mtask, req, rsp);
		break;
	default:
		if (req->op == OP_SHOW && tgt_drivers[lld_no]->show) {
			err = tgt_drivers[lld_no]->show(req->mode,
							req->tid, req->sid,
							req->cid, req->lun,
							mtask->buf, len);

			set_show_results(rsp, &err);
		} else {
			rsp->err = err;
			rsp->len = sizeof(*rsp);
		}
		break;
	}

	return err;
}

static int ipc_accept(int accept_fd)
{
	struct sockaddr addr;
	socklen_t len;
	int fd;

	len = sizeof(addr);
	fd = accept(accept_fd, (struct sockaddr *) &addr, &len);
	if (fd < 0)
		eprintf("can't accept a new connection, %m\n");
	return fd;
}

static int ipc_perm(int fd)
{
	struct ucred cred;
	socklen_t len;
	int err;

	len = sizeof(cred);
	err = getsockopt(fd, SOL_SOCKET, SO_PEERCRED, (void *) &cred, &len);
	if (err) {
		eprintf("can't get sockopt, %m\n");
		return -1;
	}

	if (cred.uid || cred.gid)
		return -EPERM;

	return 0;
}

static void mtask_handler(int fd, int events, void *data)
{
	int err, len;
	char *p;
	struct mgmt_task *mtask = data;
	struct tgtadm_req *req = &mtask->req;
	struct tgtadm_rsp *rsp = &mtask->rsp;

	switch (mtask->mtask_state) {
	case MTASK_STATE_HDR_RECV:
		len = sizeof(*req) - mtask->done;
		err = read(fd, (char *)req + mtask->done, len);
		if (err > 0) {
			mtask->done += err;
			if (mtask->done == sizeof(*req)) {
				if (req->len == sizeof(*req)) {
					tgt_mgmt(mtask);
					mtask->mtask_state =
						MTASK_STATE_RSP_SEND;
					if (tgt_event_modify(fd, EPOLLOUT))
						eprintf("failed to modify\n");

					mtask->done = 0;
				} else {
					/* the pdu exists */
					mtask->done = 0;
					mtask->mtask_state =
						MTASK_STATE_PDU_RECV;

					if (mtask->bsize < req->len) {
						eprintf("FIXME: %d\n", req->len);
						goto out;
					}
				}
			}
		} else
			if (errno != EAGAIN)
				goto out;

		break;
	case MTASK_STATE_PDU_RECV:
		len = req->len - (sizeof(*req) + mtask->done);
		err = read(fd, mtask->buf + mtask->done, len);
		if (err > 0) {
			mtask->done += err;
			if (mtask->done == req->len - (sizeof(*req))) {
				tgt_mgmt(mtask);
				mtask->mtask_state = MTASK_STATE_RSP_SEND;
				if (tgt_event_modify(fd, EPOLLOUT))
					eprintf("failed to modify\n");

				mtask->done = 0;
			}
		} else
			if (errno != EAGAIN)
				goto out;

		break;
	case MTASK_STATE_RSP_SEND:
		if (mtask->done < sizeof(*rsp)) {
			p = (char *)rsp + mtask->done;
			len = sizeof(*rsp) - mtask->done;
		} else {
			p = mtask->buf + (mtask->done - sizeof(*rsp));
			len = rsp->len - mtask->done;
		}

		err = write(fd, p, len);
		if (err > 0) {
			mtask->done += err;

			if (mtask->done == rsp->len) {
				if (req->mode == MODE_SYSTEM &&
				    req->op == OP_DELETE &&
				    !rsp->err)
					system_active = 0;

				goto out;
			}
		} else
			if (errno != EAGAIN)
				goto out;
		break;
	default:
		eprintf("unknown state %d\n", mtask->mtask_state);
	}

	return;
out:
	tgt_event_del(fd);
	free(mtask->buf);
	free(mtask);
	close(fd);
}

#define BUFSIZE 1024

static void mgmt_event_handler(int accept_fd, int events, void *data)
{
	int fd, err;
	struct mgmt_task *mtask;

	fd = ipc_accept(accept_fd);
	if (fd < 0) {
		eprintf("failed to accept a socket\n");
		return;
	}

	err = ipc_perm(fd);
	if (err < 0) {
		eprintf("permission error\n");
		goto out;
	}

	err = set_non_blocking(fd);
	if (err) {
		eprintf("failed to set a socket non-blocking\n");
		goto out;
	}

	mtask = zalloc(sizeof(*mtask));
	if (!mtask) {
		eprintf("can't allocate mtask\n");
		goto out;
	}

	mtask->buf = zalloc(BUFSIZE);
	if (!mtask->buf) {
		eprintf("can't allocate mtask buffer\n");
		free(mtask);
		goto out;
	}

	mtask->bsize = BUFSIZE;
	mtask->mtask_state = MTASK_STATE_HDR_RECV;
	err = tgt_event_add(fd, EPOLLIN, mtask_handler, mtask);
	if (err) {
		eprintf("failed to add a socket to epoll %d\n", fd);
		free(mtask->buf);
		free(mtask);
		goto out;
	}

	return;
out:
	if (fd > 0)
		close(fd);

	return;
}

int ipc_init(void)
{
	extern short control_port;
	int fd, err;
	struct sockaddr_un addr;

	fd = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (fd < 0) {
		eprintf("can't open a socket, %m\n");
		return -1;
	}

	sprintf(mgmt_path, "%s.%d", TGT_IPC_NAMESPACE, control_port);
	unlink(mgmt_path);
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_LOCAL;
	strncpy(addr.sun_path, mgmt_path, sizeof(addr.sun_path));

	err = bind(fd, (struct sockaddr *) &addr, sizeof(addr));
	if (err) {
		eprintf("can't bind a socket, %m\n");
		goto out;
	}

	err = listen(fd, 32);
	if (err) {
		eprintf("can't listen a socket, %m\n");
		goto out;
	}

	err = tgt_event_add(fd, EPOLLIN, mgmt_event_handler, NULL);
	if (err)
		goto out;

	ipc_fd = fd;

	return 0;
out:
	close(fd);
	return -1;
}

void ipc_exit(void)
{
	tgt_event_del(ipc_fd);
	close(ipc_fd);
}
