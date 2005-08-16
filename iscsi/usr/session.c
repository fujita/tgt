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

struct session *session_find_name(u32 tid, const char *iname, union iscsi_sid sid)
{
	struct session *session;
	struct target *target;

	if (!(target = target_find_by_id(tid)))
		return NULL;

	log_debug(1, "session_find_name: %s %#" PRIx64, iname, sid.id64);
	list_for_each_entry(session, &target->sessions_list, slist) {
		if (!memcmp(sid.id.isid, session->sid.id.isid, 6) &&
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

	log_debug(1, "session_find_id: %#" PRIx64, sid);
	list_for_each_entry(session, &target->sessions_list, slist) {
		if (session->sid.id64 == sid)
			return session;
	}

	return NULL;
}

static int session_test(u32 t_tid, u64 t_sid)
{
	FILE *f;
	char buf[8192], *p;
	u32 tid;
	u64 sid;
	int err = -ENOENT, find = 0;

	if ((f = fopen(PROC_SESSION, "r")) == NULL) {
		fprintf(stderr, "Can't open %s\n", PROC_SESSION);
		return -errno;
	}

	while (fgets(buf, sizeof(buf), f)) {
		p = buf;
		while (isspace((int) *p))
			p++;

		if (!strncmp(p, "tid:", 4)) {
			if (sscanf(p, "tid:%u", &tid) != 1) {
				err = -EIO;
				goto out;
			}
			if (tid == t_tid)
				find = 1;
			else
				find = 0;
		} else if (!strncmp(p, "sid:", 4)) {
			if (!find)
				continue;
			if (sscanf(p, "sid:%" SCNu64, &sid) != 1) {
				err = -EIO;
				goto out;
			}

			if (sid == t_sid) {
				err = 0;
				goto out;
			}
		}
	}

out:
	fclose(f);

	return err;
}

void session_create(struct connection *conn)
{
	struct session *session;
	static u16 tsih = 1;

	if (!(session = session_alloc(conn->tid)))
		return;

	session->sid = conn->sid;
	session->sid.id.tsih = tsih;

	while (1) {
		int err = session_test(conn->tid, session->sid.id64);

		if (err == -ENOENT)
			break;
		else if (err < 0)
			return;
		session->sid.id.tsih++;
	}
	tsih = session->sid.id.tsih + 1;

	conn->session = session;
	conn->session->initiator = strdup(conn->initiator);

	log_debug(1, "session_create: %#" PRIx64, session->sid.id64);

	ki->session_create(conn->tid, session->sid.id64, conn->exp_cmd_sn,
			   conn->max_cmd_sn, session->initiator);
	ki->param_set(conn->tid, session->sid.id64, key_session, 0, conn->session_param);
}

void session_remove(struct session *session)
{
	log_debug(1, "session_remove: %#"  PRIx64, session->sid.id64);

	if (!session->sid.id.tsih)
		ki->session_destroy(session->target->tid, session->sid.id64);

	if (session->target) {
		remque(&session->slist);
/* 		session->target->nr_sessions--; */
	}

	free(session->initiator);
	free(session);
}
