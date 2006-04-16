/*
 * SCSI RDAM Protocol lib functions
 *
 * Copyright (C) 2006 FUJITA Tomonori <tomof@acm.org>
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
#include <linux/err.h>
#include <linux/kfifo.h>
#include <linux/dma-mapping.h>
#include <libsrp.h>

static int srp_iu_pool_alloc(struct srp_queue *q, size_t max,
			     struct srp_buf **ring)
{
	int i;
	struct iu_entry *iue;

	q->pool = kcalloc(max, sizeof(struct iu_entry *), GFP_KERNEL);
	if (!q->pool)
		return -ENOMEM;
	q->items = kcalloc(max, sizeof(struct iu_entry), GFP_KERNEL);
	if (!q->items)
		goto free_pool;

	spin_lock_init(&q->lock);
	q->queue = kfifo_init((void *) q->pool, max * sizeof(void *),
			      GFP_KERNEL, &q->lock);
	if (IS_ERR(q->queue))
		goto free_item;

	for (i = 0, iue = q->items; i < max; i++) {
		__kfifo_put(q->queue, (void *) &iue, sizeof(void *));
		iue->sbuf = ring[i];
		iue++;
	}
	return 0;

free_item:
	kfree(q->items);
free_pool:
	kfree(q->pool);
	return -ENOMEM;
}

static void srp_iu_pool_free(struct srp_queue *q)
{
	kfree(q->items);
	kfree(q->pool);
}

static struct srp_buf ** srp_ring_alloc(struct device *dev,
					size_t max, size_t size)
{
	int i;
	struct srp_buf **ring;

	ring = kcalloc(max, sizeof(struct srp_buf *), GFP_KERNEL);
	if (!ring)
		return NULL;

	for (i = 0; i < max; i++) {
		ring[i] = kzalloc(sizeof(struct srp_buf), GFP_KERNEL);
		if (!ring[i])
			goto out;
		ring[i]->buf = dma_alloc_coherent(dev, size, &ring[i]->dma,
						  GFP_KERNEL);
		if (!ring[i]->buf)
			goto out;
	}
	return ring;

out:
	for (i = 0; i < max && ring[i]; i++) {
		if (ring[i]->buf)
			dma_free_coherent(dev, size, ring[i]->buf, ring[i]->dma);
		kfree(ring[i]);
	}
	kfree(ring);

	return NULL;
}

static void srp_ring_free(struct device *dev, struct srp_buf **ring, size_t max,
			  size_t size)
{
	int i;

	for (i = 0; i < max; i++) {
		dma_free_coherent(dev, size, ring[i]->buf, ring[i]->dma);
		kfree(ring[i]);
	}
}

int srp_target_alloc(struct srp_target *target, struct device *dev,
		     size_t nr, size_t iu_size)
{
	int err;

	spin_lock_init(&target->lock);
	INIT_LIST_HEAD(&target->cmd_queue);

	target->dev = dev;
	target->dev->driver_data = target;

	target->srp_iu_size = iu_size;
	target->rx_ring_size = nr;
	target->rx_ring = srp_ring_alloc(target->dev, nr, iu_size);
	if (!target->rx_ring)
		return -ENOMEM;
	err = srp_iu_pool_alloc(&target->iu_queue, nr, target->rx_ring);
	if (err)
		goto free_ring;

	return 0;

free_ring:
	srp_ring_free(target->dev, target->rx_ring, nr, iu_size);
	return -ENOMEM;
}
EXPORT_SYMBOL_GPL(srp_target_alloc);

void srp_target_free(struct srp_target *target)
{
	srp_ring_free(target->dev, target->rx_ring, target->rx_ring_size,
		      target->srp_iu_size);
	srp_iu_pool_free(&target->iu_queue);
}
EXPORT_SYMBOL_GPL(srp_target_free);

struct iu_entry *srp_iu_get(struct srp_target *target)
{
	struct iu_entry *iue = NULL;

	kfifo_get(target->iu_queue.queue, (void *) &iue, sizeof(void *));
	BUG_ON(!iue);

	iue->target = target;
	iue->scmd = NULL;
	INIT_LIST_HEAD(&iue->ilist);
	iue->flags = 0;
	return iue;
}
EXPORT_SYMBOL_GPL(srp_iu_get);

void srp_iu_put(struct iu_entry *iue)
{
	kfifo_put(iue->target->iu_queue.queue, (void *) &iue, sizeof(void *));
}
EXPORT_SYMBOL_GPL(srp_iu_put);
