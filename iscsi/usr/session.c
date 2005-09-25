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

static struct session *session_alloc(u32 tid)
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
	insque(&session->slist, &target->sessions_list);

	return session;
}

struct session *session_find_name(u32 tid, const char *iname, uint8_t *isid)
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

struct session *session_find_id(u32 tid, u64 sid)
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

	conn->session = session;
	conn->session->initiator = strdup(conn->initiator);

	log_debug("session_create: %#" PRIx64, sid);

	ki->session_create(conn->tid, sid, conn->exp_cmd_sn,
			   conn->max_cmd_sn, session->initiator);
	ki->param_set(conn->tid, sid, key_session, 0, conn->session_param);
}

void session_remove(struct session *session)
{
	uint64_t sid = sid64(session->isid, session->tsih);

	eprintf("session_remove: %#"  PRIx64, sid);

	if (!session->tsih)
		ki->session_destroy(session->target->tid, sid);

	if (session->target) {
		remque(&session->slist);
/* 		session->target->nr_sessions--; */
	}

	free(session->initiator);
	free(session);
}
