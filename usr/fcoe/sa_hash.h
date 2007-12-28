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

#ifndef _LIBSA_HASH_H_
#define _LIBSA_HASH_H_

#include "list.h"

/*
 * Hash table facility.
 */
struct sa_hash;

/*
 * Hash key value.
 */
typedef void *		sa_hash_key_t;		/* pointer hash key */
typedef u_int32_t	sa_hash_key32_t;	/* fixed-size 32-bit hash key */

struct hlist_head {
	struct hlist_node *first;
};

struct hlist_node {
	struct hlist_node *next, **pprev;
};

#define HLIST_HEAD_INIT { .first = NULL }
#define HLIST_HEAD(name) struct hlist_head name = {  .first = NULL }
#define INIT_HLIST_HEAD(ptr) ((ptr)->first = NULL)
static inline void INIT_HLIST_NODE(struct hlist_node *h)
{
	h->next = NULL;
	h->pprev = NULL;
}

static inline int hlist_unhashed(const struct hlist_node *h)
{
	return !h->pprev;
}

static inline int hlist_empty(const struct hlist_head *h)
{
	return !h->first;
}

static inline void __hlist_del(struct hlist_node *n)
{
	struct hlist_node *next = n->next;
	struct hlist_node **pprev = n->pprev;
	*pprev = next;
	if (next)
		next->pprev = pprev;
}

static inline void hlist_del(struct hlist_node *n)
{
	__hlist_del(n);
	n->next = NULL;
	n->pprev = NULL;
}

static inline void hlist_del_rcu(struct hlist_node *n)
{
	__hlist_del(n);
	n->pprev = NULL;
}

static inline void hlist_add_head_rcu(struct hlist_node *n,
					struct hlist_head *h)
{
	struct hlist_node *first = h->first;
	n->next = first;
	n->pprev = &h->first;
	if (first)
		first->pprev = &n->next;
	h->first = n;
}

#define hlist_entry(ptr, type, member) container_of(ptr,type,member)

#define prefetch(x) __builtin_prefetch(x)

#define hlist_for_each_entry_rcu(tpos, pos, head, member)		 \
	for (pos = (head)->first;					 \
	     pos && ({ prefetch(pos->next); 1;}) &&			 \
		({ tpos = hlist_entry(pos, typeof(*tpos), member); 1;}); \
	     pos = pos->next)

struct sa_hash_type {
	u_int16_t	st_link_offset;	/* offset of linkage in the element */
	int		(*st_match)(const sa_hash_key_t, void *elem);
	u_int32_t	(*st_hash)(const sa_hash_key_t);
};

/*
 * Element linkage on the hash.
 * The collision list is circular.
 */
#define sa_hash_link    hlist_node

struct sa_hash *sa_hash_create(const struct sa_hash_type *, u_int32_t size);

void sa_hash_destroy(struct sa_hash *);

void *sa_hash_lookup(struct sa_hash *, const sa_hash_key_t);

void sa_hash_insert(struct sa_hash *, const sa_hash_key_t, void *elem);

void sa_hash_insert_next(struct sa_hash *, sa_hash_key32_t *,
			 sa_hash_key32_t min_key, sa_hash_key32_t max_key,
			 void *elem);

void *sa_hash_lookup_delete(struct sa_hash *, const sa_hash_key_t);

void sa_hash_iterate(struct sa_hash *,
			void (*callback)(void *entry, void *arg), void *arg);

#endif /* _LIBSA_HASH_H_ */
