/*
 * Copyright (C) 2002-2003 Ardis Technolgies <roman@ardistech.com>
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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>

#include "iscsid.h"
#include "tgtd.h"
#include "util.h"

void conn_add_to_session(struct iscsi_connection *conn, struct iscsi_session *session)
{
	if (!list_empty(&conn->clist)) {
		eprintf("%" PRIx64 " %u\n",
			sid64(session->isid, session->tsih), conn->cid);
		exit(0);
	}

	/* release in conn_free */
	session_get(session);
	conn->session = session;
	list_add(&conn->clist, &session->conn_list);
}

struct iscsi_connection *conn_alloc(void)
{
	struct iscsi_connection *conn;

	conn = zalloc(sizeof(*conn));
	if (!conn)
		return NULL;

	conn->req_buffer = malloc(INCOMING_BUFSIZE);
	if (!conn->req_buffer) {
		free(conn);
		return NULL;
	}
	conn->rsp_buffer = malloc(INCOMING_BUFSIZE);
	if (!conn->rsp_buffer) {
		free(conn->req_buffer);
		free(conn);
		return NULL;
	}

	conn->refcount = 1;
	conn->state = STATE_FREE;
	param_set_defaults(conn->session_param, session_keys);

	INIT_LIST_HEAD(&conn->clist);
	INIT_LIST_HEAD(&conn->tx_clist);

	return conn;
}

static void conn_free(struct iscsi_connection *conn)
{
	struct iscsi_session *session = conn->session;

	dprintf("freeing connection\n");
	list_del(&conn->clist);
	free(conn->req_buffer);
	free(conn->rsp_buffer);
	free(conn->initiator);
	free(conn);

	if (session)
		session_put(session);
}

void conn_close(struct iscsi_connection *conn, int fd)
{
	struct iscsi_task *task, *tmp;

	tgt_event_del(fd);
	conn->tp->ep_close(fd);

	dprintf("connection closed\n");

	/* may not have been in FFP yet */
	if (!conn->session)
		goto done;

	/*
	 * We just closed the ep so we are not going to send/recv anything.
	 * Just free these up since they are not going to complete.
	 */
	list_for_each_entry_safe(task, tmp, &conn->session->pending_cmd_list,
				 c_list) {
		if (task->conn != conn)
			continue;

		dprintf("Forcing release of pending task %" PRIx64 "\n",
			task->tag);
		list_del(&task->c_list);
		iscsi_free_task(task);
	}

	list_for_each_entry_safe(task, tmp, &conn->tx_clist, c_list) {
		dprintf("Forcing release of tx task %" PRIx64 "\n",
			task->tag);
		list_del(&task->c_list);
		iscsi_free_task(task);
	}

	if (conn->rx_task) {
		dprintf("Forcing release of rx task %" PRIx64 "\n",
			conn->rx_task->tag);
		iscsi_free_task(conn->rx_task);
	}
	conn->rx_task = NULL;

	if (conn->tx_task) {
		dprintf("Forcing release of tx task %" PRIx64 "\n",
			conn->tx_task->tag);
		iscsi_free_task(conn->tx_task);
	}
	conn->tx_task = NULL;

done:
	conn_put(conn);
}

void conn_put(struct iscsi_connection *conn)
{
	conn->refcount--;
	if (conn->refcount == 0)
		conn_free(conn);
}

int conn_get(struct iscsi_connection *conn)
{
	/* TODO: check state */
	conn->refcount++;
	return 0;
}

struct iscsi_connection *conn_find(struct iscsi_session *session, uint32_t cid)
{
	struct iscsi_connection *conn;

	list_for_each_entry(conn, &session->conn_list, clist) {
		if (conn->cid == cid)
			return conn;
	}

	return NULL;
}

int conn_take_fd(struct iscsi_connection *conn, int fd)
{
	uint64_t sid = sid64(conn->isid, conn->tsih);

	dprintf("conn_take_fd: %d %u %u %u %" PRIx64 "\n",
		  fd, conn->cid, conn->stat_sn, conn->exp_stat_sn, sid);
	conn->session->conn_cnt++;

	return 0;
}
