/*
 * Copyright(c) 2007 Intel Corporation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <linux/if.h>

#include "list.h"
#include "log.h"
#include "util.h"

#include "sa_hash.h"

struct sa_hash {
	struct sa_hash_type sh_type;
	u_int32_t sh_mask;	/* mask for the size of the table */
	u_int32_t sh_entries;	/* number of entries now in the table */
	struct hlist_head sh_table[0];	/* table (will be allocated bigger) */
};

struct sa_hash_elem {		/* stand-in for the real client element */
	struct hlist_node elem_node;
};

static inline struct hlist_head *sa_hash_bucket(struct sa_hash *hp,
						sa_hash_key_t key)
{
	return &hp->sh_table[(*hp->sh_type.st_hash) (key) & hp->sh_mask];
}

struct sa_hash *sa_hash_create(const struct sa_hash_type *tp, uint32_t req_size)
{
	struct sa_hash *hp;
	u_int32_t size;
	size_t len;

	/*
	 * Pick power of 2 at least as big as size.
	 */
	for (size = 4; size < (1UL << 31); size <<= 1)
		if (size >= req_size)
			break;

	len = sizeof(*hp) + size * sizeof(struct hlist_head);
	hp = zalloc(len);
	if (hp) {
		hp->sh_type = *tp;
		hp->sh_mask = size - 1;
	}
	return hp;
}

void sa_hash_destroy(struct sa_hash *hp)
{
	free(hp);
}

void *sa_hash_lookup(struct sa_hash *hp, const sa_hash_key_t key)
{
	struct sa_hash_elem *ep;
	struct hlist_node *np;
	struct hlist_head *hhp;
	void *rp = NULL;

	hhp = sa_hash_bucket(hp, key);
	hlist_for_each_entry_rcu(ep, np, hhp, elem_node) {
		rp = (void *)((char *)ep - hp->sh_type.st_link_offset);
		if ((*hp->sh_type.st_match) (key, rp))
			break;
		rp = NULL;
	}
	return rp;
}

void *sa_hash_lookup_delete(struct sa_hash *hp, const sa_hash_key_t key)
{
	struct sa_hash_elem *ep;
	struct hlist_node *np;
	struct hlist_head *hhp;
	void *rp = NULL;

	hhp = sa_hash_bucket(hp, key);
	hlist_for_each_entry_rcu(ep, np, hhp, elem_node) {
		rp = (void *)((char *)ep - hp->sh_type.st_link_offset);
		if ((*hp->sh_type.st_match) (key, rp)) {
			hlist_del_rcu(np);
			hp->sh_entries--;
			break;
		}
		rp = NULL;
	}
	return (rp);
}

void sa_hash_insert(struct sa_hash *hp, const sa_hash_key_t key, void *ep)
{
	struct hlist_head *hhp;
	struct hlist_node *lp;	/* new link pointer */

	lp = (struct hlist_node *)((char *)ep + hp->sh_type.st_link_offset);
	hhp = sa_hash_bucket(hp, key);
	hlist_add_head_rcu(lp, hhp);
	hp->sh_entries++;
}

/*
 * Iterate through all hash entries.
 * For debugging.  This can be slow.
 */
void
sa_hash_iterate(struct sa_hash *hp,
		void (*callback) (void *ep, void *arg), void *arg)
{
	struct hlist_head *hhp;
	struct hlist_node *np;
	struct sa_hash_elem *ep;
	void *entry;
	int count = 0;

	for (hhp = hp->sh_table; hhp < &hp->sh_table[hp->sh_mask + 1]; hhp++) {
		hlist_for_each_entry_rcu(ep, np, hhp, elem_node) {
			entry = (void *)((char *)ep -
					 hp->sh_type.st_link_offset);
			(*callback) (entry, arg);
			count++;
		}
	}
	if (count != hp->sh_entries)
		eprintf("sh_entries %d != count %d", hp->sh_entries, count);
}
