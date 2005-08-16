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
#include <sys/stat.h>

#include "iscsid.h"

static struct qelem targets_list = LIST_HEAD_INIT(targets_list);

void target_list_build(struct connection *conn, char *addr, char *name)
{
	struct target *target;

	list_for_each_entry(target, &targets_list, tlist) {
		if (name && strcmp(target->name, name))
			continue;
		if (cops->initiator_access(target->tid, conn->fd) < 0)
			continue;

		text_key_add(conn, "TargetName", target->name);
		text_key_add(conn, "TargetAddress", addr);
	}
}

u32 target_find_by_name(const char *name)
{
	struct target *target;

	list_for_each_entry(target, &targets_list, tlist) {
		if (!strcmp(target->name, name))
			return target->tid;
	}

	return 0;
}

struct target* target_find_by_id(u32 tid)
{
	struct target *target;

	list_for_each_entry(target, &targets_list, tlist) {
		if (target->tid == tid)
			return target;
	}

	return NULL;
}

static void all_accounts_del(u32 tid, int dir)
{
	char name[ISCSI_NAME_LEN], pass[ISCSI_NAME_LEN];

	for (memset(name, 0, sizeof(name));
	     cops->account_query(tid, dir, name, pass) != -ENOENT;) {
		cops->account_del(tid, dir, name);
	}

}

int target_del(u32 tid)
{
	int err;
	struct target* target;

	if (!(target = target_find_by_id(tid)))
		return -ENOENT;

	if (target->nr_sessions)
		return -EBUSY;

	if ((err = ki->target_destroy(tid)) < 0)
		return err;

	remque(&target->tlist);

	if (!list_empty(&target->sessions_list)) {
		fprintf(stderr, "%s still have sessions %d\n", __FUNCTION__, tid);
		exit(-1);
	}

	all_accounts_del(tid, AUTH_DIR_INCOMING);
	all_accounts_del(tid, AUTH_DIR_OUTGOING);

	free(target);

	return 0;
}

int target_add(u32 *tid, char *name)
{
	struct target *target;
	int err;

	if (!name)
		return -EINVAL;

	if (!(target = malloc(sizeof(*target))))
		return -ENOMEM;

	memset(target, 0, sizeof(*target));
	memcpy(target->name, name, sizeof(target->name) - 1);

	if ((err = ki->target_create(tid, name)) < 0) {
		log_warning("can't create a target %d %u\n", errno, *tid);
		goto out;
	}

	INIT_LIST_HEAD(&target->tlist);
	INIT_LIST_HEAD(&target->sessions_list);
	target->tid = *tid;
	insque(&target->tlist, &targets_list);

	return 0;
out:
	free(target);
	return err;
}
