/*
 * Core Target Framework code
 *
 * (C) 2005 FUJITA Tomonori <tomof@acm.org>
 * (C) 2005 Mike Christie <michaelc@cs.wisc.edu>
 * This code is licenced under the GPL.
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/mempool.h>
#include <linux/blkdev.h>
#include <linux/file.h>
#include <asm/scatterlist.h>

#include <tgt.h>
#include <tgt_target.h>
#include <tgt_device.h>
#include <tgt_if.h>
#include <tgt_protocol.h>

#include "tgt_priv.h"

MODULE_LICENSE("GPL");

static spinlock_t all_targets_lock;
static LIST_HEAD(all_targets);

static spinlock_t target_tmpl_lock;
static LIST_HEAD(target_tmpl_list);

static spinlock_t device_tmpl_lock;
static LIST_HEAD(device_tmpl_list);

static struct target_type_internal *target_template_get(const char *name)
{
	unsigned long flags;
	struct target_type_internal *ti;

	spin_lock_irqsave(&target_tmpl_lock, flags);

	list_for_each_entry(ti, &target_tmpl_list, list)
		if (!strcmp(name, ti->tt->name)) {
			if (!try_module_get(ti->tt->module))
				ti = NULL;
			spin_unlock_irqrestore(&target_tmpl_lock, flags);
			return ti;
		}

	spin_unlock_irqrestore(&target_tmpl_lock, flags);

	return NULL;
}

static void target_template_put(struct tgt_target_template *tt)
{
	module_put(tt->module);
}

int tgt_target_template_register(struct tgt_target_template *tt)
{
	static atomic_t target_type_id = ATOMIC_INIT(0);
	unsigned long flags;
	struct target_type_internal *ti;
	int err;

	ti = kzalloc(sizeof(*ti), GFP_KERNEL);
	if (!ti)
		return -ENOMEM;

	INIT_LIST_HEAD(&ti->list);
	ti->tt = tt;

	ti->proto = tgt_protocol_get(tt->protocol);
	if (!ti->proto) {
		eprintk("Could not find %s protocol\n", tt->protocol);
		kfree(ti);
		return -EINVAL;
	}

	ti->typeid = atomic_add_return(1, &target_type_id);

	err = tgt_sysfs_register_type(ti);
	if (err)
		goto proto_put;

	/* set some defaults if not set */

	/*
	 * If the driver imposes no hard sector transfer limit, start at
	 * machine infinity initially.
	 */
	if (!tt->max_sectors)
		tt->max_sectors = TGT_DEFAULT_MAX_SECTORS;
	/*
	 * assume a 4GB boundary, if not set
	 */
	if (!tt->seg_boundary_mask)
		tt->seg_boundary_mask = 0xffffffff;

	if (!tt->max_segment_size)
		tt->max_segment_size = MAX_SEGMENT_SIZE;

	if (!tt->max_hw_segments)
		tt->max_hw_segments = MAX_HW_SEGMENTS;

	spin_lock_irqsave(&target_tmpl_lock, flags);
	list_add_tail(&ti->list, &target_tmpl_list);
	spin_unlock_irqrestore(&target_tmpl_lock, flags);

	return 0;

proto_put:
	tgt_protocol_put(ti->proto);
	kfree(ti);

	return err;
}
EXPORT_SYMBOL_GPL(tgt_target_template_register);

void tgt_target_template_unregister(struct tgt_target_template *tt)
{
	unsigned long flags;
	struct target_type_internal *ti;

	spin_lock_irqsave(&target_tmpl_lock, flags);

	list_for_each_entry(ti, &target_tmpl_list, list)
		if (ti->tt == tt) {
			list_del(&ti->list);
			goto found;
		}
	ti = NULL;
found:
	spin_unlock_irqrestore(&target_tmpl_lock, flags);

	if (ti) {
		tgt_protocol_put(ti->proto);
		tgt_sysfs_unregister_type(ti);
	}
}
EXPORT_SYMBOL_GPL(tgt_target_template_unregister);

static void tgt_request_fn(struct request_queue *q)
{
	struct tgt_cmd *cmd;
	struct request *rq;
	int err;

	while ((rq = elv_next_request(q)) != NULL) {
		/* we need to set state or refcount under this lock! */
		cmd = rq->special;

		/*
		 * the iosched nicely ordered these, should we try to keep the
		 * ordering or for most cases will it not make a difference
		 * since the lower levels will iosched again (not for
		 * passthrough though). Maybe we should use a tgt_device
		 * flag to indicate what is best for the real device.
		 */
		if (atomic_read(&cmd->state) != TGT_CMD_READY)
			break;
		/*
		 * hit queue depth (command completion will run the
		 * queue again
		 */
		if (blk_queue_tagged(q) && blk_queue_start_tag(q, rq))
			break;

		spin_unlock_irq(q->queue_lock);

		dprintk("cmd %p tag %d\n", cmd, rq->tag);

		if (!cmd->device) {
			struct tgt_target *target = cmd->session->target;

			INIT_WORK(&cmd->work, target->proto->uspace_cmd_execute,
				  cmd);
			queue_work(target->twq, &cmd->work);
			err = TGT_CMD_USPACE_QUEUED;
		} else
			err = cmd->device->dt->execute_cmd(cmd);
	        switch (err) {
	        case TGT_CMD_FAILED:
		case TGT_CMD_COMPLETED:
			dprintk("command completed %d\n", err);
			tgt_transfer_response(cmd);
		default:
			dprintk("command %d queued to real dev\n", rq->tag);
		}

		spin_lock_irq(q->queue_lock);
	}
}

static void tgt_queue_destroy(struct request_queue *q)
{
	blk_cleanup_queue(q);
}

static int tgt_queue_create(struct tgt_protocol *proto, int depth,
			    struct request_queue **queue)
{
	struct request_queue *q;
	int err = -ENOMEM;

	*queue = q = blk_init_queue(tgt_request_fn, NULL);
	if (!q)
		return -ENOMEM;

	elevator_exit(q->elevator);
	err = elevator_init(q, "noop");
	if (err)
		goto out;

	/* who should set this limit ? */
	err = blk_queue_init_tags(q, depth, NULL);
	if (err)
		goto out;

	return 0;
out:
	tgt_queue_destroy(q);
	return err;
}

struct tgt_target *target_find(int tid)
{
	struct tgt_target *target;

	spin_lock(&all_targets_lock);
	list_for_each_entry(target, &all_targets, tlist) {
		if (target->tid == tid)
			goto found;
	}
	target = NULL;
found:
	spin_unlock(&all_targets_lock);

	return target;
}

struct tgt_target *tgt_target_create(char *target_type, int queued_cmds)
{
	char name[16];
	static int target_id;
	struct tgt_target *target;
	struct target_type_internal *ti;

	target = kzalloc(sizeof(*target), GFP_KERNEL);
	if (!target)
		return NULL;

	ti = target_template_get(target_type);
	if (!ti)
		goto free_target;

	target->state = TGT_CREATED;
	target->tt = ti->tt;
	target->proto = ti->proto;
	target->typeid = ti->typeid;
	target->tid = target_id++;
	spin_lock_init(&target->lock);

	INIT_LIST_HEAD(&target->session_list);
	INIT_LIST_HEAD(&target->device_list);

	target->queued_cmds = queued_cmds;

	snprintf(name, sizeof(name), "tgtd%d", target->tid);
	target->twq = create_workqueue(name);
	if (!target->twq)
		goto put_template;

	target->tt_data = kzalloc(target->tt->priv_data_size, GFP_KERNEL);
	if (!target->tt_data)
		goto free_workqueue;

	if (target->tt->target_create)
		if (target->tt->target_create(target))
			goto free_priv_tt_data;

	if (tgt_queue_create(target->proto, queued_cmds ? : TGT_QUEUE_DEPTH,
			     &target->q))
		goto tt_destroy;

	if (tgt_sysfs_register_target(target))
		goto queue_destroy;

	spin_lock(&all_targets_lock);
	list_add(&target->tlist, &all_targets);
	spin_unlock(&all_targets_lock);
	return target;

queue_destroy:
	tgt_queue_destroy(target->q);
tt_destroy:
	if (target->tt->target_destroy)
		target->tt->target_destroy(target);
free_priv_tt_data:
	kfree(target->tt_data);
free_workqueue:
	destroy_workqueue(target->twq);
put_template:
	target_template_put(target->tt);
free_target:
	kfree(target);
	return NULL;
}
EXPORT_SYMBOL_GPL(tgt_target_create);

int tgt_target_destroy(struct tgt_target *target)
{
	unsigned long flags;

	dprintk("%p\n", target);

	spin_lock_irqsave(&target->lock, flags);
	if (!list_empty(&target->device_list)) {
		spin_unlock_irqrestore(&target->lock, flags);
		return -EBUSY;
	}
	/* userspace and maybe a hotunplug are racing (TODO refcounts) */
	if (target->state == TGT_DESTROYED)
		return -ENODEV;
	target->state = TGT_DESTROYED;
	spin_unlock_irqrestore(&target->lock, flags);

	spin_lock(&all_targets_lock);
	list_del(&target->tlist);
	spin_unlock(&all_targets_lock);

	if (target->tt->target_destroy)
		target->tt->target_destroy(target);

	destroy_workqueue(target->twq);
	tgt_queue_destroy(target->q);
	target_template_put(target->tt);
	tgt_sysfs_unregister_target(target);

	return 0;
}
EXPORT_SYMBOL_GPL(tgt_target_destroy);

static void tgt_session_op_init(struct tgt_session *session,
				void (*func)(void *),
				tgt_session_done_t *done, void *arg)
{
	session->done = done;
	session->arg = arg;
	INIT_WORK(&session->work, func, session);
	queue_work(session->target->twq, &session->work);
}

static void tgt_session_async_create(void *data)
{
	struct tgt_session *session = (struct tgt_session *) data;
	struct tgt_target *target = session->target;
	struct tgt_protocol *proto = session->target->proto;
	unsigned long flags;
	int err = 0;

	session->cmd_pool = mempool_create(TGT_MAX_CMD, mempool_alloc_slab,
					   mempool_free_slab, proto->cmd_cache);
	if (!session->cmd_pool)
		err = -ENOMEM;

	if (!err) {
		spin_lock_irqsave(&target->lock, flags);
		list_add(&session->slist, &target->session_list);
		spin_unlock_irqrestore(&target->lock, flags);
	}

	session->done(session->arg, err ? NULL : session);
	if (err)
		kfree(session);
}

int tgt_session_create(struct tgt_target *target, tgt_session_done_t *done,
		       void *arg)
{
	struct tgt_session *session;

	BUG_ON(!done);
	session = kzalloc(sizeof(*session), GFP_ATOMIC);
	if (!session)
		return -ENOMEM;
	session->target = target;
	INIT_LIST_HEAD(&session->slist);

	tgt_session_op_init(session, tgt_session_async_create, done, arg);

	return 0;
}
EXPORT_SYMBOL_GPL(tgt_session_create);

static void tgt_session_async_destroy(void *data)
{
	struct tgt_session *session = (struct tgt_session *) data;
	struct tgt_target *target = session->target;
	unsigned long flags;

	spin_lock_irqsave(&target->lock, flags);
	list_del(&session->slist);
	spin_unlock_irqrestore(&target->lock, flags);

	if (session->done)
		session->done(session->arg, NULL);

	mempool_destroy(session->cmd_pool);
	kfree(session);
}

int tgt_session_destroy(struct tgt_session *session,
			tgt_session_done_t *done, void *arg)
{
	tgt_session_op_init(session, tgt_session_async_destroy,
			    done, arg);
	return 0;
}
EXPORT_SYMBOL_GPL(tgt_session_destroy);

struct device_type_internal {
	struct tgt_device_template *sdt;
	struct list_head list;
};

static struct tgt_device_template *device_template_get(const char *name)
{
	unsigned long flags;
	struct device_type_internal *ti;

	spin_lock_irqsave(&device_tmpl_lock, flags);

	list_for_each_entry(ti, &device_tmpl_list, list)
		if (!strcmp(name, ti->sdt->name)) {
			if (!try_module_get(ti->sdt->module))
				ti = NULL;
			spin_unlock_irqrestore(&device_tmpl_lock, flags);
			return ti ? ti->sdt : NULL;
		}

	spin_unlock_irqrestore(&device_tmpl_lock, flags);

	return NULL;
}

static void device_template_put(struct tgt_device_template *sdt)
{
	module_put(sdt->module);
}

int tgt_device_template_register(struct tgt_device_template *sdt)
{
	unsigned long flags;
	struct device_type_internal *ti;

	ti = kzalloc(sizeof(*ti), GFP_KERNEL);
	if (!ti)
		return -ENOMEM;

	INIT_LIST_HEAD(&ti->list);
	ti->sdt = sdt;

	spin_lock_irqsave(&device_tmpl_lock, flags);
	list_add_tail(&ti->list, &device_tmpl_list);
	spin_unlock_irqrestore(&device_tmpl_lock, flags);

	return 0;
}
EXPORT_SYMBOL_GPL(tgt_device_template_register);

void tgt_device_template_unregister(struct tgt_device_template *sdt)
{
	unsigned long flags;
	struct device_type_internal *ti;

	spin_lock_irqsave(&device_tmpl_lock, flags);

	list_for_each_entry(ti, &device_tmpl_list, list)
		if (ti->sdt == sdt) {
			list_del(&ti->list);
			kfree(ti);
			break;
		}

	spin_unlock_irqrestore(&device_tmpl_lock, flags);
}
EXPORT_SYMBOL_GPL(tgt_device_template_unregister);

/*
 * TODO: use a hash or any better alg/ds
 */
static struct tgt_device *
tgt_device_find_nolock(struct tgt_target *target, uint64_t dev_id)
{
	struct tgt_device *device;

	list_for_each_entry(device, &target->device_list, dlist)
		if (device->dev_id == dev_id)
			return device;

	return NULL;
}

static struct tgt_device *tgt_device_find(struct tgt_target *target, uint64_t dev_id)
{
	static struct tgt_device *device;
	unsigned long flags;

	spin_lock_irqsave(&target->lock, flags);
	device = tgt_device_find_nolock(target, dev_id);
	spin_unlock_irqrestore(&target->lock, flags);

	return device;
}

struct tgt_device *tgt_device_get(struct tgt_target *target, uint64_t dev_id)
{
	static struct tgt_device *device;
	unsigned long flags;

	spin_lock_irqsave(&target->lock, flags);
	device = tgt_device_find_nolock(target, dev_id);
	if (device) {
		if (test_bit(TGT_DEV_DEL, &device->state))
			device = NULL;
		else
			class_device_get(&device->cdev);
	}
	spin_unlock_irqrestore(&target->lock, flags);

	return device;
}
EXPORT_SYMBOL_GPL(tgt_device_get);

void tgt_device_put(struct tgt_device *device)
{
	class_device_put(&device->cdev);
}
EXPORT_SYMBOL_GPL(tgt_device_put);

#define min_not_zero(l, r) (l == 0) ? r : ((r == 0) ? l : min(l, r))

static int tgt_device_queue_setup(struct tgt_device *device)
{
	struct io_restrictions *limits = &device->limits;
	struct tgt_target_template *tt = device->target->tt;
	struct request_queue *q = device->q;

	device->q = q;

	blk_queue_max_sectors(q, min_not_zero(tt->max_sectors,
					limits->max_sectors));
	blk_queue_max_phys_segments(q, min_not_zero(limits->max_phys_segments,
					(unsigned short)TGT_MAX_PHYS_SEGMENTS));
	blk_queue_max_hw_segments(q, min_not_zero(tt->max_hw_segments,
					limits->max_hw_segments));
	blk_queue_max_segment_size(q, min_not_zero(tt->max_segment_size,
					limits->max_segment_size));
	blk_queue_segment_boundary(q, min_not_zero(tt->seg_boundary_mask,
					limits->seg_boundary_mask));
	if (!tt->use_clustering || !device->use_clustering)
		clear_bit(QUEUE_FLAG_CLUSTER, &q->queue_flags);

	dprintk("max_sectors %u\n", q->max_sectors);
	dprintk("max_phys_segments %u\n", q->max_phys_segments);
	dprintk("max_hw_segments %u\n", q->max_hw_segments);
	dprintk("max_segment_size %u\n", q->max_segment_size);
	dprintk("seg_boundary_mask %lx\n", q->seg_boundary_mask);
	if (test_bit(QUEUE_FLAG_CLUSTER, &q->queue_flags))
		dprintk("clustering set\n");
	else
		dprintk("clustering not set\n");

	return 0;
}

int tgt_device_create(int tid, uint64_t dev_id, char *device_type,
		      int fd, unsigned long dflags)
{
	struct tgt_target *target;
	struct tgt_device *device;
	unsigned long flags;

	dprintk("tid %d dev_id %" PRIu64 " type %s fd %d\n",
		tid, dev_id, device_type, fd);

	target = target_find(tid);
	if (!target)
		return -EINVAL;

	device = kzalloc(sizeof(*device), GFP_KERNEL);
	if (!device)
		return -ENOMEM;

	device->dev_id = dev_id;
	device->target = target;
	device->fd = fd;

	device->file = fget(fd);
	if (!device->file) {
		eprintk("Could not get fd %d\n", fd);
		goto free_device;
	}

	device->dt = device_template_get(device_type);
	if (!device->dt) {
		eprintk("Could not get devive type %s\n", device_type);
		goto put_fd;
	}

	device->dt_data = kzalloc(device->dt->priv_data_size, GFP_KERNEL);
	if (!device->dt_data)
		goto put_template;

	if (device->dt->create)
		if (device->dt->create(device))
			goto free_priv_dt_data;

	if (tgt_queue_create(target->proto, TGT_QUEUE_DEPTH, &device->q))
		goto dt_destroy;
	tgt_device_queue_setup(device);

	if (tgt_sysfs_register_device(device))
		goto queue_destroy;

	spin_lock_irqsave(&target->lock, flags);
	list_add(&device->dlist, &target->device_list);
	spin_unlock_irqrestore(&target->lock, flags);

	return 0;

queue_destroy:
	tgt_queue_destroy(device->q);
dt_destroy:
	if (device->dt->destroy)
		device->dt->destroy(device);
free_priv_dt_data:
	kfree(device->dt_data);
put_template:
	device_template_put(device->dt);
put_fd:
	fput(device->file);
free_device:
	kfree(device);
	return -EINVAL;
}

void tgt_device_free(struct tgt_device *device)
{
	struct tgt_target *target = device->target;
	unsigned long flags;

	dprintk("%d %lld\n", target->tid, (unsigned long long) device->dev_id);

	spin_lock_irqsave(&target->lock, flags);
	list_del(&device->dlist);
	spin_unlock_irqrestore(&target->lock, flags);

	if (device->dt->destroy)
		device->dt->destroy(device);

	tgt_queue_destroy(device->q);
	fput(device->file);
	device_template_put(device->dt);

	kfree(device->dt_data);
	kfree(device);
}

int tgt_device_destroy(int tid, uint64_t dev_id)
{
	struct tgt_device *device;
	struct tgt_target *target;
	unsigned long flags;
	int err = 0;

	target = target_find(tid);
	if (!target)
		return -ENOENT;

	/*
	 * We cannot delete the device from the list because
	 * uspace_cmd_done would use it later.
	 */
	spin_lock_irqsave(&target->lock, flags);
	device = tgt_device_find_nolock(target, dev_id);
	if (device)
		err = test_and_set_bit(TGT_DEV_DEL, &device->state);
	spin_unlock_irqrestore(&target->lock, flags);

	if (!device)
		return -ENOENT;

	if (err) {
		eprintk("the device is being removed %d %lld\n",
			tid, (unsigned long long) dev_id);
		return -EBUSY;
	} else {
		/* TODO: revoke commands in the devece queue here. */
		tgt_sysfs_unregister_device(device);
		return 0;
	}
}

static void tgt_free_buffer(struct tgt_cmd *cmd)
{
	int i;

	for (i = 0; i < cmd->sg_count; i++)
		__free_page(cmd->sg[i].page);
	kfree(cmd->sg);
}

static void __tgt_cmd_destroy(void *data)
{
	struct tgt_cmd *cmd = data;
	struct request *rq = cmd->rq;
	struct request_queue *q = rq->q;
	unsigned long flags;

	dprintk("tag %d\n", rq->tag);
	spin_lock_irqsave(q->queue_lock, flags);
	if (blk_rq_tagged(rq))
		blk_queue_end_tag(q, rq);
	end_that_request_last(rq);
	spin_unlock_irqrestore(q->queue_lock, flags);

	if (cmd->device)
		tgt_device_put(cmd->device);

	mempool_free(cmd, cmd->session->cmd_pool);

	blk_run_queue(q);
}

static void tgt_cmd_destroy(struct tgt_cmd *cmd)
{
	dprintk("cmd %p\n", cmd);

	tgt_free_buffer(cmd);

	/*
	 * Goose the queue incase we are blocked on a queue depth
	 * limit or resource problem.
	 *
	 * This is run from a interrpt handler normally so we queue
	 * the work
	 */
	INIT_WORK(&cmd->work, __tgt_cmd_destroy, cmd);
	queue_work(cmd->session->target->twq, &cmd->work);
}

void tgt_transfer_response(void *data)
{
	struct tgt_cmd *cmd = data;
	struct tgt_target *target = cmd->session->target;
	int err;

	cmd->done = tgt_cmd_destroy;
	err = target->tt->transfer_response(cmd);
	switch (err) {
	case TGT_CMD_XMIT_FAILED:
	case TGT_CMD_XMIT_REQUEUE:
		/*
		 * TODO add a real queue to avoid re-orders and starvation
		 * for now just reschedule.
		 */
		INIT_WORK(&cmd->work, tgt_transfer_response, cmd);
		queue_delayed_work(cmd->session->target->twq, &cmd->work,
				   10 * HZ);
		break;
	}
}
EXPORT_SYMBOL_GPL(tgt_transfer_response);

struct tgt_cmd *
tgt_cmd_create(struct tgt_session *session, void *tgt_priv, uint8_t *cb,
	       uint32_t data_len, enum dma_data_direction data_dir,
	       uint8_t *dev_buf, int dev_buf_size, int flags)
{
	struct tgt_cmd *cmd;

	cmd = mempool_alloc(session->cmd_pool, GFP_ATOMIC);
	if (!cmd) {
		eprintk("Could not allocate tgt_cmd for %p\n", session);
		return NULL;
	}
	memset(cmd, 0, sizeof(*cmd));
	session->target->proto->cmd_create(cmd, cb, data_len, data_dir,
					   dev_buf, dev_buf_size, flags);

	cmd->device = tgt_device_get(session->target, cmd->dev_id);
	cmd->session = session;
	cmd->private = tgt_priv;
	cmd->done = tgt_cmd_destroy;
	atomic_set(&cmd->state, TGT_CMD_CREATED);

	dprintk("%p %p\n", session, cmd);

	tgt_cmd_start(cmd);

	return cmd;
}
EXPORT_SYMBOL_GPL(tgt_cmd_create);

static int tgt_cmd_queue(struct tgt_cmd *cmd, gfp_t gfp_mask)
{
	int write = (cmd->data_dir == DMA_TO_DEVICE);
	struct request_queue *q;
	struct request *rq;

	if (cmd->device)
		q = cmd->device->q;
	else
		q = cmd->session->target->q;

	rq = blk_get_request(q, write, gfp_mask);
	if (!rq)
		return -ENOMEM;

	cmd->rq = rq;
	rq->special = cmd;
	rq->flags |= REQ_SPECIAL | REQ_SOFTBARRIER | REQ_NOMERGE | REQ_BLOCK_PC;
	elv_add_request(q, rq, ELEVATOR_INSERT_BACK, 0);
	return 0;
}

static void set_cmd_ready(struct tgt_cmd *cmd)
{
	unsigned long flags;
	struct request_queue *q = cmd->rq->q;

	/*
	 * we have a request that is ready for processing so
	 * plug the queue
	 */
	spin_lock_irqsave(q->queue_lock, flags);
	atomic_set(&cmd->state, TGT_CMD_READY);
	blk_plug_device(q);
	spin_unlock_irqrestore(q->queue_lock, flags);
}

static void tgt_write_data_transfer_done(struct tgt_cmd *cmd)
{
	/*
	 * TODO check for errors and add state checking. we may have
	 * to internally queue for the target driver
	 */
	set_cmd_ready(cmd);
}

#define pgcnt(size, offset)	((((size) + ((offset) & ~PAGE_CACHE_MASK)) + PAGE_CACHE_SIZE - 1) >> PAGE_CACHE_SHIFT)

/*
 * TODO: this will have to obey at least the target driver's limits,
 * but to support passthrough commands we will need to obey the
 * something like's tgt_sd devices's queue's limits.
 */
void __tgt_alloc_buffer(struct tgt_cmd *cmd)
{
	uint64_t offset = cmd->offset;
	uint32_t len = cmd->bufflen;
	int i;

	cmd->sg_count = pgcnt(len, offset);
	offset &= ~PAGE_CACHE_MASK;

	dprintk("cmd %p tag %d pg_count %d offset %" PRIu64 " len %d\n",
		cmd, cmd->rq->tag, cmd->sg_count, cmd->offset, cmd->bufflen);

	/*
	 * TODO: mempool this like in scsi_lib.c
	 */
	cmd->sg = kmalloc(cmd->sg_count * sizeof(struct scatterlist),
			   GFP_KERNEL | __GFP_NOFAIL);

	/*
	 * TODO need to create reserves
	 */
	for (i = 0; i < cmd->sg_count; i++) {
		struct scatterlist *sg = &cmd->sg[i];

		sg->page = alloc_page(GFP_KERNEL | __GFP_NOFAIL);
		sg->offset = offset;
		sg->length = min_t(uint32_t, PAGE_CACHE_SIZE - offset, len);

		offset = 0;
		len -= sg->length;
	}
}

static void tgt_alloc_buffer(void *data)
{
	struct tgt_cmd *cmd = data;

	__tgt_alloc_buffer(cmd);
	atomic_set(&cmd->state, TGT_CMD_BUF_ALLOCATED);

	/*
	 * we probably will not be able to rely on the target
	 * driver knowing the data_dir so this may have to move
	 * the devices or protocol if it becomes command specific
	 */
	if (cmd->data_dir == DMA_TO_DEVICE) {
		cmd->done = tgt_write_data_transfer_done;
		/*
		 * TODO handle errors and possibly requeue for the
		 * target driver
		 */
		cmd->session->target->tt->transfer_write_data(cmd);
	} else
		set_cmd_ready(cmd);
}

int tgt_cmd_start(struct tgt_cmd *cmd)
{
	struct tgt_session *session = cmd->session;
	int err;

	if (cmd->device)
		cmd->device->dt->prep_cmd(cmd);

	err = tgt_cmd_queue(cmd, GFP_ATOMIC);
	if (err)
		return err;

	if (cmd->bufflen) {
		atomic_set(&cmd->state, TGT_CMD_STARTED);
		INIT_WORK(&cmd->work, tgt_alloc_buffer, cmd);
		queue_work(session->target->twq, &cmd->work);
	} else
		set_cmd_ready(cmd);

	return 0;
}
EXPORT_SYMBOL_GPL(tgt_cmd_start);

static struct tgt_cmd *find_cmd_by_id(struct request_queue *q, uint64_t cid)
{

	struct request *rq;

	rq = blk_queue_find_tag(q, cid);
	if (rq)
		return rq->special;
	return NULL;
}

int uspace_cmd_done(int tid, uint64_t dev_id, uint64_t cid, void *data,
		    int result, uint32_t len)
{
	struct tgt_target *target;
	struct tgt_device *device;
	struct tgt_cmd *cmd;
	struct request_queue *q;
	char *p = data;
	int i;

	dprintk("%d %llu %llu\n", tid, (unsigned long long) dev_id,
		(unsigned long long) cid);

	target = target_find(tid);
	if (!target) {
		eprintk("Could not find target %d\n", tid);
		return -EINVAL;
	}

	if (dev_id == TGT_INVALID_DEV_ID)
		q = target->q;
	else {
		device = tgt_device_find(target, dev_id);
		if (!device) {
			eprintk("Could not find device %llu\n",
				(unsigned long long) dev_id);
			return -EINVAL;
		}
		q = device->q;
	}

	cmd = find_cmd_by_id(q, cid);
	if (!cmd) {
		eprintk("Could not find command %llu\n",
			(unsigned long long) cid);
		return -EINVAL;
	}

	dprintk("cmd %p tag %d result %d len %d bufflen %u\n",
		cmd, cmd->rq->tag, result, len, cmd->bufflen);

	if (len) {
		/*
		 * yuck TODO fix.
		 * This will happen if we thought we were going to do some
		 * IO but we ended up just gettting some sense back
		 */
		if (len != cmd->bufflen) {
			tgt_free_buffer(cmd);

			cmd->bufflen = len;
			cmd->offset = 0;

			__tgt_alloc_buffer(cmd);
		}

		for (i = 0; i < cmd->sg_count; i++) {
			uint32_t copy = min_t(uint32_t, len, PAGE_CACHE_SIZE);

			memcpy(page_address(cmd->sg[i].page), p, copy);
			p += copy;
			len -= copy;
		}
	}

	cmd->result = result;
	target->proto->uspace_cmd_complete(cmd);
	tgt_transfer_response(cmd);

	return 0;
}

static void __exit tgt_exit(void)
{
	tgt_nl_exit();
	tgt_sysfs_exit();
}

static int __init tgt_init(void)
{
	int err = -ENOMEM;

	spin_lock_init(&all_targets_lock);
	spin_lock_init(&target_tmpl_lock);
	spin_lock_init(&device_tmpl_lock);

	tgt_protocol_init();

	err = tgt_sysfs_init();
	if (err)
		return err;

	err = tgt_nl_init();
	if (err)
		goto out;

	return 0;
out:
	tgt_sysfs_exit();
	return err;
}

module_init(tgt_init);
module_exit(tgt_exit);
