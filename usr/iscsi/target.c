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

static LIST_HEAD(targets_list);

void target_list_build(struct connection *conn, char *addr, char *name)
{
	struct target *target;

	list_for_each_entry(target, &targets_list, tlist) {
		if (name && strcmp(target->name, name))
			continue;
/* 		if (cops->initiator_access(target->tid, conn->fd) < 0) */
/* 			continue; */

		text_key_add(conn, "TargetName", target->name);
		text_key_add(conn, "TargetAddress", addr);
	}
}

struct target *target_find_by_name(const char *name)
{
	struct target *target;

	list_for_each_entry(target, &targets_list, tlist) {
		if (!strcmp(target->name, name))
			return target;
	}

	return NULL;
}

struct target* target_find_by_id(int tid)
{
	struct target *target;

	list_for_each_entry(target, &targets_list, tlist) {
		if (target->tid == tid)
			return target;
	}

	return NULL;
}

int iscsi_target_destroy(int tid)
{
	struct target* target;

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
	struct target *target;
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

	if (!name)
		return -EINVAL;

	dprintf("%d %s\n", tid, name);

	target = malloc(sizeof(*target));
	if (!target)
		return -ENOMEM;

	memset(target, 0, sizeof(*target));
	memcpy(target->name, name, sizeof(target->name) - 1);

	memcpy(target->session_param, default_tgt_session_param,
	       sizeof(target->session_param));

	INIT_LIST_HEAD(&target->tlist);
	INIT_LIST_HEAD(&target->sessions_list);
	target->tid = tid;
	list_add(&target->tlist, &targets_list);

	return 0;
}

int iscsi_target_update(int tid, char *name)
{
	int idx, err;
	unsigned int val;
	char *str;
	struct target* target;

	target = target_find_by_id(tid);
	if (!target)
		return -ENOENT;

	str = name + strlen(name) + 1;

	idx = param_index_by_name(name, session_keys);
	if (idx < 0)
		return idx;

	err = param_str_to_val(session_keys, idx, str, &val);
	if (err)
		return err;

	err = param_check_val(session_keys, idx, &val);
	if (err < 0)
		return err;

	target->session_param[idx].val = val;

	dprintf("%s %s %u\n", name, str, val);

	return 0;
}


int iscsi_target_show(int tid, char *buf, int rest)
{
	struct target* target;

	if (!(target = target_find_by_id(tid)))
		return 0;

	return snprintf(buf, rest, ": %s\n", target->name);
}
