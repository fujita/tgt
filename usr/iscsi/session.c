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

static LIST_HEAD(sessions_list);

static struct session *session_alloc(int tid)
{
	struct session *session;
	struct target *target = target_find_by_id(tid);

	if (!target)
		return NULL;
	if (!(session = malloc(sizeof(*session))))
		return NULL;
	memset(session, 0, sizeof(*session));

	session->target = target;
	INIT_LIST_HEAD(&session->slist);
	list_add(&session->slist, &target->sessions_list);

	INIT_LIST_HEAD(&session->conn_list);

	return session;
}

int iscsi_target_bind(int hostno)
{
	struct session *session;

	list_for_each_entry(session, &sessions_list, hlist) {
		if (session->hostno == hostno)
			return session->target->tid;
	}

	return -ENOENT;
}

struct session *session_find_name(int tid, const char *iname, uint8_t *isid)
{
	struct session *session;
	struct target *target;

	if (!(target = target_find_by_id(tid)))
		return NULL;

	log_debug("session_find_name: %s %x %x %x %x %x %x", iname,
		  isid[0], isid[1], isid[2], isid[3], isid[4], isid[5]);
	list_for_each_entry(session, &target->sessions_list, slist) {
		if (!memcmp(isid, session->isid, sizeof(session->isid)) &&
		    !strcmp(iname, session->initiator))
			return session;
	}

	return NULL;
}

struct session *session_find_id(int tid, uint64_t sid)
{
	struct session *session;
	struct target *target;

	if (!(target = target_find_by_id(tid)))
		return NULL;

	log_debug("session_find_id: %#" PRIx64, sid);
	list_for_each_entry(session, &target->sessions_list, slist) {
		if (sid64(session->isid, session->tsih) == sid)
			return session;
	}

	return NULL;
}

void session_create(struct connection *conn)
{
	struct session *session;
	uint64_t sid;
	static uint16_t tsih = 1;

	/* First, we need to get an available sid. */
	while (1) {
		sid = sid64(conn->isid, tsih);
		if (!session_find_id(conn->tid, sid))
			break;
		tsih++;
	}

	session = session_alloc(conn->tid);
	if (!session)
		return;

	memcpy(session->isid, conn->isid, sizeof(session->isid));
	session->tsih = tsih++;

	conn_add_to_session(conn, session);
	conn->session->initiator = strdup(conn->initiator);

	log_debug("session_create: %#" PRIx64, sid);

	ki->create_session(thandle, conn->exp_cmd_sn, &session->ksid,
			   &session->hostno);

	list_add(&session->hlist, &sessions_list);
}

void session_remove(struct session *session)
{
	uint64_t sid = sid64(session->isid, session->tsih);

	eprintf("%#"  PRIx64 "\n", sid);

	if (!list_empty(&session->conn_list))
		eprintf("%" PRIx64 " conn_list is not null\n", sid);

	if (!session->tsih)
		ki->destroy_session(thandle, session->ksid);

	if (session->target) {
		list_del(&session->slist);
/* 		session->target->nr_sessions--; */
	}

	list_del(&session->hlist);

	free(session->initiator);
	free(session);
}
