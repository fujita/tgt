/*
 * SCSI target account management functions
 *
 * Copyright (C) 2006 FUJITA Tomonori <tomof@acm.org>
 * Copyright (C) 2006 Mike Christie <michaelc@cs.wisc.edu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "iscsid.h"
#include "tgtadm.h"
#include "util.h"

enum {
	ACCOUNT_INVALID,
	ACCOUNT_INCOMING,
	ACCOUNT_OUTGOING,
};

struct iscsi_account {
	struct list_head ac_list;

	char *user;
	char *password;

	int type;
	uint32_t id;

	struct ac_head ach;
};

static LIST_HEAD(accounts_list);

static struct iscsi_account *iscsi_lookup_account(uint32_t id)
{
	struct iscsi_account *pos;

	list_for_each_entry(pos, &accounts_list, ac_list) {
		if (pos->id == id)
			return pos;
	}
	return NULL;
}

static int iscsi_create_account(void)
{
	static uint32_t id;
	uint32_t new_id;
	struct iscsi_account *ac;

	for (new_id = id + 1; iscsi_lookup_account(new_id) && new_id == id;
	     new_id++)
		;
	if (new_id == id) {
		eprintf("Too many accounts\n");
		return EINVAL;
	}

	ac = zalloc(sizeof(*ac));
	if (!ac)
		return ENOMEM;

	ac->id = id = new_id;
	ac->type = ACCOUNT_INVALID;
	ac->ach.first = NULL;

	list_add(&ac->ac_list, &accounts_list);

	return 0;
}

static int iscsi_account_update(uint32_t uid, char *name)
{
	int err = EINVAL;
	char *str;
	struct iscsi_account *ac;

	ac = iscsi_lookup_account(uid);
	if (!ac)
		return ENOENT;

	str = name + strlen(name) + 1;

	if (!strcmp(name, "Type")) {
		if (ac->type != ACCOUNT_INVALID)
			return err;

		if (!strcmp(str, "Incoming")) {
			err = 0;
			ac->type = ACCOUNT_INCOMING;
		} else if (!strcmp(str, "Outgoing")) {
			err = 0;
			ac->type = ACCOUNT_OUTGOING;
		}

	} else if (!strcmp(name, "User")) {
		if (ac->user)
			free(ac->user);
		ac->user = strdup(str);
		if (ac->user)
			err = 0;
		else
			err = ENOMEM;
	} else if (!strcmp(name, "Password")) {
		if (ac->password)
			free(ac->password);
		ac->password = strdup(str);
		if (ac->password)
			err = 0;
		else
			err = ENOMEM;
	}

	return err;
}

static void __account_bind(struct iscsi_account *ac, struct ac_node *acn)
{
	acn->head = &ac->ach;
	acn->next = ac->ach.first;
	ac->ach.first = acn;
}

static int iscsi_account_bind(int tid, uint32_t uid)
{
	int i, err;
	struct iscsi_target* target;
	struct iscsi_account *ac, *tmp;
	struct ac_node *acn;

	target = target_find_by_id(tid);
	if (!target)
		return ENOENT;

	ac = iscsi_lookup_account(uid);
	if (!ac)
		return ENOENT;

	if (!ac->user || !ac->password) {
		eprintf("You must set user and password first\n");
		return EINVAL;
	}

	err = EINVAL;
	if (ac->type == ACCOUNT_INCOMING) {
		acn = target->incoming;
		for (i = 0; i < ARRAY_SIZE(target->incoming); i++, acn++) {
			if (acn->head) {
				tmp = container_of(acn->head, struct iscsi_account, ach);
				if (tmp->id == ac->id) {
					eprintf("This target already has this account\n");
					break;
				}
			} else {
				__account_bind(ac, acn);
				err = 0;
				break;
			}
		}
		if (err)
			eprintf("This target cannot have any more account\n");

	} else if (ac->type == ACCOUNT_OUTGOING) {
		if (target->outgoing.head)
			eprintf("This target already has the outgoing account\n");
		else {
			__account_bind(ac, &target->outgoing);
			err = 0;
		}
	} else
		eprintf("You must set account type first\n");

	return err;
}

#define print_account(buf, rest, ac)				\
snprintf(buf, rest, "aid:%u Type:%s User:%s Password:%s\n",	\
	(ac)->id, ac_type[(ac)->type], (ac)->user ? : "Empty",	\
	(ac)->password ? : "Empty")

static int iscsi_show_account(int tid, uint32_t uid, char *buf, int rest)
{
	int len, i, total = 0;
	char *ac_type[] = {"Invalid", "Incoming", "Outgoing"};
	struct iscsi_account *ac;
	struct ac_node *acn;

	if (tid == -1) {
		list_for_each_entry(ac, &accounts_list, ac_list) {
			len = print_account(buf, rest, ac);
			buffer_check(buf, total, len, rest);
		}
	} else {
		struct iscsi_target* target;

		target = target_find_by_id(tid);
		if (!target)
			goto out;

		acn = target->incoming;
		for (i = 0; i < ARRAY_SIZE(target->incoming); i++, acn++) {
			if (!acn->head)
				continue;

			ac = container_of(acn->head, struct iscsi_account, ach);
			len = print_account(buf, rest, ac);
			buffer_check(buf, total, len, rest);
		}

		acn = &target->outgoing;
		if (!acn->head)
			goto out;
		ac = container_of(acn->head, struct iscsi_account, ach);
		len = print_account(buf, rest, ac);
		total += len;
	}
out:
	return total;
}

int iscsi_mgmt_account(uint32_t op, int tid, uint32_t uid, char *param, char *buf, int len)
{
	int err = EINVAL;

	switch (op) {
	case OP_NEW:
		err = iscsi_create_account();
		break;
	case OP_DELETE:
		eprintf("Not implemented yet\n");
		break;
	case OP_UPDATE:
		err = iscsi_account_update(uid, param);
		break;
	case OP_BIND:
		err = iscsi_account_bind(tid, uid);
		break;
	case OP_UNBIND:
		eprintf("Not implemented yet\n");
		break;
	case OP_SHOW:
		err = iscsi_show_account(tid, uid, buf, len);
		break;
	default:
		break;
	}

	eprintf("%d\n", err);

	return err;
}

int iscsi_account_available(int tid, int dir)
{
	int err = 0;
	struct iscsi_target* target;
	struct ac_node *acn;

	target = target_find_by_id(tid);
	if (!target)
		return ENOENT;

	if (dir == AUTH_DIR_INCOMING) {
		int i;

		acn = target->incoming;
		for (i = 0;  i < ARRAY_SIZE(target->incoming); i++, acn++) {
			if (acn->head) {
				err = 1;
				break;
			}
		}

	} else if (dir == AUTH_DIR_OUTGOING) {
		acn = &target->outgoing;
		if (acn->head)
			err = 1;
	}

	return err;
}

int iscsi_account_lookup(int tid, int dir, char *user, char *pass)
{
	int err = ENOENT;
	struct iscsi_target* target;
	struct iscsi_account *ac;
	struct ac_node *acn;

	target = target_find_by_id(tid);
	if (!target)
		return err;

	if (dir == AUTH_DIR_INCOMING) {
		int i;

		acn = target->incoming;
		for (i = 0;  i < ARRAY_SIZE(target->incoming); i++, acn++) {
			if (acn->head) {
				ac = container_of(acn->head, struct iscsi_account, ach);
				if (!strcmp(ac->user, user)) {
					strncpy(pass, ac->password, ISCSI_NAME_LEN);
					err = 0;
				}
			}
		}
	} else if (dir == AUTH_DIR_OUTGOING) {
		acn = &target->outgoing;
		if (acn->head) {
			ac = container_of(acn->head, struct iscsi_account, ach);
			strncpy(user, ac->user, ISCSI_NAME_LEN);
			strncpy(pass, ac->password, ISCSI_NAME_LEN);
			err = 0;
		}
	} else
		eprintf("Invalid direction\n");

	return err;
}
