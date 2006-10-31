/*
 * Copyright (C) 2002-2003 Ardis Technolgies <roman@ardistech.com>
 *
 * Released under the terms of the GNU GPL v2.0.
 */

#include <ctype.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/stat.h>
#include <errno.h>

#include "iscsid.h"
#include "util.h"

static LIST_HEAD(sessions_list);

struct session *session_find_name(int tid, const char *iname, uint8_t *isid)
{
	struct session *session;
	struct target *target;

	if (!(target = target_find_by_id(tid)))
		return NULL;

	dprintf("session_find_name: %s %x %x %x %x %x %x\n", iname,
		  isid[0], isid[1], isid[2], isid[3], isid[4], isid[5]);
	list_for_each_entry(session, &target->sessions_list, slist) {
		if (!memcmp(isid, session->isid, sizeof(session->isid)) &&
		    !strcmp(iname, session->initiator))
			return session;
	}

	return NULL;
}

struct session *session_lookup(uint16_t tsih)
{
	struct session *session;
	list_for_each_entry(session, &sessions_list, hlist) {
		if (session->tsih == tsih)
			return session;
	}
	return NULL;
}

int session_create(struct connection *conn)
{
	struct session *session = NULL;
	static uint16_t tsih, last_tsih = 0;
	struct target *target;

	target = target_find_by_id(conn->tid);
	if (!target)
		return -EINVAL;

	for (tsih = last_tsih + 1; tsih != last_tsih; tsih++) {
		if (!tsih)
			continue;
		session = session_lookup(tsih);
		if (!session)
			break;
	}
	if (session)
		return -EINVAL;

	session = zalloc(sizeof(*session));
	if (!session)
		return -ENOMEM;

	session->target = target;
	INIT_LIST_HEAD(&session->slist);
	list_add(&session->slist, &target->sessions_list);

	INIT_LIST_HEAD(&session->conn_list);
	INIT_LIST_HEAD(&session->cmd_list);
	INIT_LIST_HEAD(&session->pending_cmd_list);

	memcpy(session->isid, conn->isid, sizeof(session->isid));
	session->tsih = last_tsih = tsih;

	conn_add_to_session(conn, session);
	conn->session->initiator = strdup(conn->initiator);

	dprintf("session_create: %#" PRIx64 "\n", sid64(conn->isid, session->tsih));

	list_add(&session->hlist, &sessions_list);
	session->exp_cmd_sn = conn->exp_cmd_sn;

	return 0;
}

void session_destroy(struct session *session)
{
	eprintf("%d\n", session->tsih);

	if (!list_empty(&session->conn_list)) {
		eprintf("%d conn_list is not null\n", session->tsih);
		return;
	}

	if (session->target) {
		list_del(&session->slist);
/* 		session->target->nr_sessions--; */
	}

	list_del(&session->hlist);

	free(session->initiator);
	free(session);
}

void session_get(struct session *session)
{
	session->refcount++;
}

void session_put(struct session *session)
{
	session->refcount--;
	if (session->refcount == 0)
		session_destroy(session);
}
