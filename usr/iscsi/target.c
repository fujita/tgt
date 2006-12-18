/*
 * Copyright (C) 2002-2003 Ardis Technolgies <roman@ardistech.com>
 *
 * Released under the terms of the GNU GPL v2.0.
 */

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <linux/netlink.h>
#include <sys/socket.h>
#include "iscsid.h"
#include "tgtadm.h"
#include "tgtd.h"

static LIST_HEAD(targets_list);

void target_list_build(struct iscsi_connection *conn, char *addr, char *name)
{
	struct iscsi_target *target;

	list_for_each_entry(target, &targets_list, tlist) {
		if (name && strcmp(tgt_targetname(target->tid), name))
			continue;
/* 		if (cops->initiator_access(target->tid, conn->fd) < 0) */
/* 			continue; */

		text_key_add(conn, "TargetName", tgt_targetname(target->tid));
		text_key_add(conn, "TargetAddress", addr);
	}
}

struct iscsi_target *target_find_by_name(const char *name)
{
	struct iscsi_target *target;

	list_for_each_entry(target, &targets_list, tlist) {
		if (!strcmp(tgt_targetname(target->tid), name))
			return target;
	}

	return NULL;
}

struct iscsi_target* target_find_by_id(int tid)
{
	struct iscsi_target *target;

	list_for_each_entry(target, &targets_list, tlist) {
		if (target->tid == tid)
			return target;
	}

	return NULL;
}

int iscsi_target_destroy(int tid)
{
	struct iscsi_target* target;

	if (!(target = target_find_by_id(tid)))
		return -ENOENT;

	if (target->nr_sessions)
		return -EBUSY;

	if (!list_empty(&target->sessions_list)) {
		eprintf("bug still have sessions %d\n", tid);
		exit(-1);
	}

	list_del(&target->tlist);

	free(target);

	return 0;
}

int iscsi_target_create(int tid, char *name)
{
	struct iscsi_target *target;
	struct param default_tgt_session_param[] = {
		{0, 8192},
		{0, 8192},
		{0, DIGEST_NONE},
		{0, DIGEST_NONE},
		{0, 1},
		{0, 1},
		{0, 1},
		{0, 65536},
		{0, 262144},
		{0, 1},
		{0, 1},
		{0, 0},
		{0, 0},
		{0, 0},
		{0, 2},
		{0, 20},
		{0, 2048},
		{0, 2048},
		{0, 1},
	};

	target = malloc(sizeof(*target));
	if (!target)
		return -ENOMEM;

	memset(target, 0, sizeof(*target));

	memcpy(target->session_param, default_tgt_session_param,
	       sizeof(target->session_param));

	INIT_LIST_HEAD(&target->tlist);
	INIT_LIST_HEAD(&target->sessions_list);
	target->tid = tid;
	list_add(&target->tlist, &targets_list);

	return 0;
}

static int iscsi_session_param_update(struct iscsi_target* target, int idx, char *str)
{
	int err;
	unsigned int val;

	err = param_str_to_val(session_keys, idx, str, &val);
	if (err)
		return err;

	err = param_check_val(session_keys, idx, &val);
	if (err < 0)
		return err;

	target->session_param[idx].val = val;

	dprintf("%s %s %u\n", session_keys[idx].name, str, val);

	return 0;
}

int iscsi_target_update(int tid, char *name)
{
	int idx, err = -EINVAL;
	char *str;
	struct iscsi_target* target;

	target = target_find_by_id(tid);
	if (!target)
		return -ENOENT;

	str = name + strlen(name) + 1;

	dprintf("%s:%s\n", name, str);

	idx = param_index_by_name(name, session_keys);
	if (idx >= 0)
		err = iscsi_session_param_update(target, idx, str);
	return err;
}

static int show_iscsi_param(char *buf, struct param *param, int rest)
{
	int i, len, total;
	char value[64];
	struct iscsi_key *keys = session_keys;

	for (i = total = 0; session_keys[i].name; i++) {
		param_val_to_str(keys, i, param[i].val, value);
		len = snprintf(buf, rest, "%s=%s\n", keys[i].name, value);
		buffer_check(buf, total, len, rest);
	}

	return total;
}

static int iscsi_target_show_connection(struct iscsi_target* target, uint64_t sid,
					uint32_t cid, char *buf, int rest)
{
	int len, total = 0;
	struct iscsi_session *session;
	struct iscsi_connection *conn;

	session = session_lookup(sid_to_tsih(sid));
	if (!session)
		return 0;

	len = 0;
	list_for_each_entry(conn, &session->conn_list, clist) {
		if (conn->cid == cid || !cid) {
			if (cid) {
			} else {
				len = snprintf(buf, rest, "cid:%u", conn->cid);
				buffer_check(buf, total, len, rest);

				len = 0;
				if (conn->tp->ep_show) {
					len = conn->tp->ep_show(conn->fd, buf, rest);
					buffer_check(buf, total, len, rest);
				}

				if (!len) {
					len = snprintf(buf, rest, "\n");
					buffer_check(buf, total, len, rest);
				}
			}
		}
	}

	return total;
}

static int iscsi_target_show_session(struct iscsi_target* target, uint64_t sid,
				     char *buf, int rest)
{
	int len, total = 0;
	struct iscsi_session *session;

	list_for_each_entry(session, &target->sessions_list, slist) {
		if (sid64(session->isid, session->tsih) == sid || !sid) {
			if (sid)
				len = show_iscsi_param(buf, session->session_param, rest);
			else
				len = snprintf(buf, rest, "sid:%" PRIu64 " initiator:%s\n",
					       sid64(session->isid, session->tsih),
					       session->initiator);
			buffer_check(buf, total, len, rest);
		}
	}

	return total;
}

int iscsi_target_show(int mode, int tid, uint64_t sid, uint32_t cid, uint64_t lun,
		      char *buf, int rest)
{
	struct iscsi_target* target;
	int len, total = 0;

	target = target_find_by_id(tid);
	if (!target)
		return 0;

	switch (mode) {
	case MODE_TARGET:
		len = show_iscsi_param(buf, target->session_param, rest);
		total += len;
		break;
	case MODE_SESSION:
		len = iscsi_target_show_session(target, sid, buf, rest);
		total += len;
		break;
	case MODE_CONNECTION:
		len = iscsi_target_show_connection(target, sid, cid, buf, rest);
		total += len;
		break;
	default:
		break;
	}

	return total;
}
