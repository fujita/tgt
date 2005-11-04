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
#include "tgtadm.h"

struct qelem targets_list = LIST_HEAD_INIT(targets_list);

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

int target_find_by_name(const char *name, int *tid)
{
	struct target *target;

	list_for_each_entry(target, &targets_list, tlist) {
		if (!strcmp(target->name, name)) {
			*tid = target->tid;
			return 0;
		}
	}

	return -ENOENT;
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
