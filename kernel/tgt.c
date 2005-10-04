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
#include <linux/hash.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/mempool.h>
#include <linux/netlink.h>
#include <linux/file.h>
#include <asm/scatterlist.h>
#include <net/tcp.h>

#include <tgt.h>
#include <tgt_target.h>
#include <tgt_device.h>
#include <tgt_if.h>
#include <tgt_protocol.h>

#define DEBUG_TGT

#define eprintk(fmt, args...)					\
do {								\
	printk("%s(%d) " fmt, __FUNCTION__, __LINE__, args);	\
} while (0)

#ifdef DEBUG_TGT
#define dprintk eprintk
#else
#define dprintk(fmt, args...)
#endif

MODULE_LICENSE("GPL");

static spinlock_t all_targets_lock;
static LIST_HEAD(all_targets);

static spinlock_t target_tmpl_lock;
static LIST_HEAD(target_tmpl_list);

static spinlock_t device_tmpl_lock;
static LIST_HEAD(device_tmpl_list);

static int tgtd_pid;
static struct sock *nls;

/* TODO: lock per session */
static spinlock_t cmd_hash_lock;
#define TGT_HASH_ORDER		8
#define	cmd_hashfn(key)	hash_long((key), TGT_HASH_ORDER)
static struct list_head cmd_hash[1 << TGT_HASH_ORDER];

struct target_type_internal {
	struct list_head list;
	struct tgt_target_template *tt;
	struct tgt_protocol *proto;
};

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
	unsigned long flags;
	struct target_type_internal *ti;

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

	spin_lock_irqsave(&target_tmpl_lock, flags);
	list_add_tail(&ti->list, &target_tmpl_list);
	spin_unlock_irqrestore(&target_tmpl_lock, flags);

	return 0;
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
			tgt_protocol_put(ti->proto);
			kfree(ti);
			break;
		}

	spin_unlock_irqrestore(&target_tmpl_lock, flags);
}
EXPORT_SYMBOL_GPL(tgt_target_template_unregister);

static struct tgt_target *target_find(int tid)
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

	if (!tgtd_pid) {
		eprintk("%s\n", "Run the user-space daemon first!");
		return NULL;
	}

	target = kzalloc(sizeof(*target), GFP_KERNEL);
	if (!target)
		return NULL;

	ti = target_template_get(target_type);
	if (!ti)
		goto free_target;

	target->tt = ti->tt;
	target->proto = ti->proto;
	target->tid = target_id++;
	spin_lock_init(&target->lock);

	INIT_LIST_HEAD(&target->session_list);
	INIT_LIST_HEAD(&target->device_list);
	INIT_LIST_HEAD(&target->work_list);

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

	if (tgt_sysfs_register_target(target))
		goto tt_destroy;

	spin_lock(&all_targets_lock);
	list_add(&target->tlist, &all_targets);
	spin_unlock(&all_targets_lock);
	return target;

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
	dprintk("%p\n", target);

	spin_lock(&all_targets_lock);
	list_del(&target->tlist);
	spin_unlock(&all_targets_lock);

	if (target->tt->target_destroy)
		target->tt->target_destroy(target);

	destroy_workqueue(target->twq);
	target_template_put(target->tt);
	tgt_sysfs_unregister_target(target);

	return 0;
}
EXPORT_SYMBOL_GPL(tgt_target_destroy);

static int session_init(struct tgt_session *session, int max_cmds)
{
	struct tgt_target *target = session->target;
	struct tgt_protocol *proto = session->target->proto;
	unsigned long flags;

	session->cmd_pool = mempool_create(max_cmds, mempool_alloc_slab,
					mempool_free_slab, proto->cmd_cache);
	if (!session->cmd_pool)
		goto out;

	spin_lock_irqsave(&target->lock, flags);
	list_add(&session->slist, &target->session_list);
	spin_unlock_irqrestore(&target->lock, flags);

	return 0;
out:
	if (session->cmd_pool)
		mempool_destroy(session->cmd_pool);

	return -ENOMEM;
}

struct async_session_data {
	struct tgt_session *session;
	struct work_struct work;
	int cmds;
	void (*done)(void *, struct tgt_session *);
	void *arg;
};

static void session_async_create(void *data)
{
	struct async_session_data *async
		= (struct async_session_data *) data;
	int err;

	err = session_init(async->session, async->cmds);
	if (err)
		kfree(async->session);
	async->done(async->arg, err ? NULL : async->session);
	kfree(async);
}

struct tgt_session *
tgt_session_create(struct tgt_target *target,
		   int max_cmds,
		   void (*done)(void *, struct tgt_session *),
		   void *arg)
{
	struct tgt_session *session;
	struct async_session_data *async;

	BUG_ON(!target);

	if (done && !arg) {
		eprintk("Need arg %d!\n", target->tid);
		return NULL;
	}

	dprintk("%p %d\n", target, max_cmds);

	session = kzalloc(sizeof(*session), done ? GFP_ATOMIC : GFP_KERNEL);
	if (!session)
		return NULL;

	session->target = target;
	INIT_LIST_HEAD(&session->slist);

	if (done) {
		async = kmalloc(sizeof(*async), GFP_ATOMIC);
		if (!async)
			goto out;

		async->session = session;
		async->cmds = max_cmds;
		async->done = done;
		async->arg = arg;

		INIT_WORK(&async->work, session_async_create, async);
		queue_work(session->target->twq, &async->work);
		return session;
	}

	if (session_init(session, max_cmds) < 0)
		goto out;

	return session;

out:
	kfree(session);
	return NULL;
}
EXPORT_SYMBOL_GPL(tgt_session_create);

int tgt_session_destroy(struct tgt_session *session)
{
	mempool_destroy(session->cmd_pool);
	kfree(session);

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

struct tgt_device *tgt_device_find(struct tgt_target *target, uint64_t dev_id)
{
	static struct tgt_device *device;
	unsigned long flags;

	spin_lock_irqsave(&target->lock, flags);
	device = tgt_device_find_nolock(target, dev_id);
	spin_unlock_irqrestore(&target->lock, flags);

	return device;
}
EXPORT_SYMBOL_GPL(tgt_device_find);

static int tgt_device_create(int tid, uint64_t dev_id, char *device_type,
			     int fd, unsigned long dflags)
{
	struct tgt_target *target;
	struct tgt_device *device;
	unsigned long flags;

	dprintk("tid %d dev_id %llu type %s fd %d\n",
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

	device->pt_data =
		kzalloc(target->proto->priv_dev_data_size, GFP_KERNEL);
	if (!device->pt_data)
		goto free_priv_dt_data;

	if (device->dt->create)
		if (device->dt->create(device))
			goto free_priv_pt_data;

	if (target->proto->attach_device)
		target->proto->attach_device(device->pt_data);

	if (tgt_sysfs_register_device(device))
		goto dt_destroy;

	spin_lock_irqsave(&target->lock, flags);
	list_add(&device->dlist, &target->device_list);
	spin_unlock_irqrestore(&target->lock, flags);

	return 0;

dt_destroy:
	if (device->dt->destroy)
		device->dt->destroy(device);
free_priv_pt_data:
	kfree(device->pt_data);
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

static int tgt_device_destroy(int tid, uint64_t dev_id)
{
	struct tgt_device *device;
	struct tgt_target *target;
	unsigned long flags;

	target = target_find(tid);
	if (!target)
		return -ENOENT;

	spin_lock_irqsave(&target->lock, flags);
	device = tgt_device_find_nolock(target, dev_id);
	spin_unlock_irqrestore(&target->lock, flags);
	if (!device)
		return -EINVAL;

	list_del(&device->dlist);
	if (device->dt->destroy)
		device->dt->destroy(device);

	if (target->proto->detach_device)
		target->proto->detach_device(device->pt_data);

	fput(device->file);
	device_template_put(device->dt);
	tgt_sysfs_unregister_device(device);

	return 0;
}

void tgt_transfer_response(void *data)
{
	struct tgt_cmd *cmd = data;
	struct tgt_target *target = cmd->session->target;
	int err;

	if (target->proto->dequeue_cmd)
		target->proto->dequeue_cmd(cmd);

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
	};
}
EXPORT_SYMBOL_GPL(tgt_transfer_response);

static void queuecommand(void *data)
{
	int err = 0;
	struct tgt_cmd *cmd = data;
	struct tgt_target *target = cmd->session->target;
	struct tgt_device *device = cmd->device;

	dprintk("cid %llu\n", cmd->cid);

	/* Should we do this earlier? */
	if (!device)
		cmd->device = device = tgt_device_find(target, cmd->dev_id);
	if (device)
		dprintk("found %llu\n", cmd->dev_id);

	err = target->proto->queue_cmd(cmd);

	switch (err) {
	case TGT_CMD_FAILED:
	case TGT_CMD_COMPLETED:
		dprintk("command completed %d\n", err);
		tgt_transfer_response(cmd);
	default:
		dprintk("command %llu queued\n", cmd->cid);
	};
}

struct tgt_cmd *tgt_cmd_create(struct tgt_session *session, void *tgt_priv)
{
	struct tgt_cmd *cmd;
	unsigned long flags;

	cmd = mempool_alloc(session->cmd_pool, GFP_ATOMIC);
	if (!cmd) {
		eprintk("Could not allocate tgt_cmd for %p\n", session);
		return NULL;
	}

	memset(cmd, 0, sizeof(*cmd));
	cmd->session = session;
	cmd->cid = (uint64_t) (unsigned long) cmd;
	cmd->private = tgt_priv;
	INIT_LIST_HEAD(&cmd->clist);
	INIT_LIST_HEAD(&cmd->hash_list);

	dprintk("%p %llu\n", session, cmd->cid);

	spin_lock_irqsave(&cmd_hash_lock, flags);
	list_add_tail(&cmd->hash_list, &cmd_hash[cmd_hashfn(cmd->cid)]);
	spin_unlock_irqrestore(&cmd_hash_lock, flags);

	return cmd;
}
EXPORT_SYMBOL_GPL(tgt_cmd_create);

static void tgt_free_buffer(struct tgt_cmd *cmd)
{
	int i;

	for (i = 0; i < cmd->sg_count; i++)
		__free_page(cmd->sg[i].page);
	kfree(cmd->sg);
}

void tgt_cmd_destroy(struct tgt_cmd *cmd)
{
	unsigned long flags;

	dprintk("cid %llu\n", cmd->cid);

	tgt_free_buffer(cmd);

	spin_lock_irqsave(&cmd_hash_lock, flags);
	list_del(&cmd->hash_list);
	spin_unlock_irqrestore(&cmd_hash_lock, flags);

	mempool_free(cmd, cmd->session->cmd_pool);
}
EXPORT_SYMBOL_GPL(tgt_cmd_destroy);

static int __tgt_cmd_queue(struct tgt_cmd *cmd)
{
	struct tgt_session *session = cmd->session;

	/*
	 * we may need to code so that other layers can override this
	 * done function
	 */
	cmd->done = tgt_cmd_destroy;
	INIT_WORK(&cmd->work, queuecommand, cmd);
	queue_work(session->target->twq, &cmd->work);
	return 0;
}

static void tgt_write_data_transfer_done(struct tgt_cmd *cmd)
{
	/*
	 * TODO check for errors and add state checking. we may have
	 * to internally queue for the target driver
	 */

	/*
	 * we are normally called from a irq so since the tgt_vsd blocks
	 * we must queue this cmd
	 */
	__tgt_cmd_queue(cmd);
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

	dprintk("cid %llu pg_count %d offset %llu len %d\n", cmd->cid,
		cmd->sg_count, cmd->offset, cmd->bufflen);

	cmd->sg = kmalloc(cmd->sg_count * sizeof(struct scatterlist),
			   GFP_KERNEL | __GFP_NOFAIL);

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
		queuecommand(cmd);
}

void tgt_cmd_alloc_buffer(struct tgt_cmd *cmd)
{
	struct tgt_session *session = cmd->session;
	BUG_ON(!list_empty(&cmd->clist));

	INIT_WORK(&cmd->work, tgt_alloc_buffer, cmd);
	queue_work(session->target->twq, &cmd->work);
}
EXPORT_SYMBOL_GPL(tgt_cmd_alloc_buffer);

int tgt_cmd_queue(struct tgt_cmd *cmd)
{
	if (cmd->bufflen)
		tgt_cmd_alloc_buffer(cmd);
	else
		__tgt_cmd_queue(cmd);
	return 0;
}
EXPORT_SYMBOL_GPL(tgt_cmd_queue);

int tgt_uspace_cmd_send(struct tgt_cmd *cmd)
{
	struct tgt_protocol *proto = cmd->session->target->proto;
	struct sk_buff *skb;
	struct nlmsghdr *nlh;
	struct tgt_event *ev;
	char *pdu;
	int len, proto_pdu_size = proto->uspace_pdu_size;

	len = NLMSG_SPACE(sizeof(*ev) + proto_pdu_size);
	skb = alloc_skb(NLMSG_SPACE(len), GFP_KERNEL);
	if (!skb)
		return -ENOMEM;

	dprintk("%d %Zd %d\n", len, sizeof(*ev), proto_pdu_size);
	nlh = __nlmsg_put(skb, tgtd_pid, 0, TGT_KEVENT_CMD_REQ,
			  len - sizeof(*nlh), 0);
	ev = NLMSG_DATA(nlh);
	memset(ev, 0, sizeof(*ev));

	pdu = (char *) ev->data;
	ev->k.cmd_req.tid = cmd->session->target->tid;
	ev->k.cmd_req.dev_id = cmd->dev_id;
	ev->k.cmd_req.cid = cmd->cid;

	proto->build_uspace_pdu(cmd, pdu);

	return netlink_unicast(nls, skb, tgtd_pid, 0);
}
EXPORT_SYMBOL_GPL(tgt_uspace_cmd_send);

static void uspace_cmd_done(struct tgt_cmd *cmd, void *data,
			     int result, uint32_t len)
{
	struct tgt_device *device = cmd->device;
	char *p = data;
	int i;

	dprintk("cid %llu result %d len %d bufflen %u\n",
		cmd->cid, result, len, cmd->bufflen);

	if (len) {
		/*
		 * yuck TODO fix.
		 * This will happen if we though we were going to do some
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
	if (device->dt->complete_uspace_cmd)
		device->dt->complete_uspace_cmd(cmd);
	tgt_transfer_response(cmd);
}

static struct tgt_cmd *find_cmd_by_id(uint64_t cid)
{
	struct list_head *head;
	struct tgt_cmd *cmd;
	unsigned long flags;

	head = &cmd_hash[cmd_hashfn(cid)];

	spin_lock_irqsave(&cmd_hash_lock, flags);

	list_for_each_entry(cmd, head, hash_list) {
		if (cmd->cid == cid)
			goto found;
	}
	cmd = NULL;
found:
	spin_unlock_irqrestore(&cmd_hash_lock, flags);

	return cmd;
}

int tgt_msg_send(struct tgt_target *target, void *data, int data_len,
		 unsigned int gfp_flags)
{
	struct tgt_event *ev;
	struct sk_buff *skb;
	struct nlmsghdr *nlh;
	int len;

	len = NLMSG_SPACE(sizeof(*ev) + data_len);
	skb = alloc_skb(len, gfp_flags);
	if (!skb)
		return -ENOMEM;

	dprintk("%d %Zd %d\n", len, sizeof(*ev), data_len);
	nlh = __nlmsg_put(skb, tgtd_pid, 0, TGT_KEVENT_TARGET_PASSTHRU,
			 len - sizeof(*nlh), 0);
	ev = NLMSG_DATA(nlh);
	memset(ev, 0, sizeof(*ev));

	memcpy(ev->data, data, data_len);
	ev->k.tgt_passthru.tid = target->tid;
	ev->k.tgt_passthru.len = data_len;

	return netlink_unicast(nls, skb, tgtd_pid, 0);
}
EXPORT_SYMBOL_GPL(tgt_msg_send);

static int event_recv_msg(struct sk_buff *skb, struct nlmsghdr *nlh)
{
	int err = 0;
	struct tgt_event *ev = NLMSG_DATA(nlh);
	struct tgt_cmd *cmd;
	struct tgt_target *target;

	dprintk("%d %d %d\n", nlh->nlmsg_type,
		nlh->nlmsg_pid, current->pid);

	switch (nlh->nlmsg_type) {
	case TGT_UEVENT_START:
		tgtd_pid  = NETLINK_CREDS(skb)->pid;
		dprintk("start %d\n", tgtd_pid);
		break;
	case TGT_UEVENT_TARGET_CREATE:
		target = tgt_target_create(ev->u.c_target.type,
					   ev->u.c_target.nr_cmds);
		if (target)
			err = target->tid;
		else
			err = -EINVAL;
		break;
	case TGT_UEVENT_TARGET_DESTROY:
		target = target_find(ev->u.d_target.tid);
		if (target)
			err = tgt_target_destroy(target);
		else
			err = -EINVAL;
		break;
	case TGT_UEVENT_TARGET_PASSTHRU:
		target = target_find(ev->u.tgt_passthru.tid);
		if (!target || !target->tt->msg_recv) {
			dprintk("Could not find target %d for passthru\n",
				ev->u.tgt_passthru.tid);
			err = -EINVAL;
			break;
		}

		err = target->tt->msg_recv(target, ev->u.tgt_passthru.len,
					   ev->data);
		break;
	case TGT_UEVENT_DEVICE_CREATE:
		err = tgt_device_create(ev->u.c_device.tid,
					ev->u.c_device.dev_id,
					ev->u.c_device.type,
					ev->u.c_device.fd,
					ev->u.c_device.flags);
		break;
	case TGT_UEVENT_DEVICE_DESTROY:
		err = tgt_device_destroy(ev->u.d_device.tid,
					 ev->u.d_device.dev_id);
		break;
	case TGT_UEVENT_CMD_RES:
		cmd = find_cmd_by_id(ev->u.cmd_res.cid);
		if (cmd)
			uspace_cmd_done(cmd, ev->data,
					 ev->u.cmd_res.result,
					 ev->u.cmd_res.len);
		else {
			eprintk("cannot found %llu\n", ev->u.cmd_res.cid);
			err = -EEXIST;
		}
		break;
	default:
		eprintk("unknown type %d\n", nlh->nlmsg_type);
		err = -EINVAL;
	}

	return err;
}

static int send_event_res(uint32_t pid, uint16_t type, void *data, uint32_t size)
{
	struct nlmsghdr *nlh;
	struct sk_buff *skb;
	uint32_t len = NLMSG_SPACE(size);

	skb = alloc_skb(len, GFP_KERNEL | __GFP_NOFAIL);
	nlh = __nlmsg_put(skb, pid, 0, type, size, 0);
	memcpy(NLMSG_DATA(nlh), data, size);

	return netlink_unicast(nls, skb, pid, 0);
}

static int event_recv_skb(struct sk_buff *skb)
{
	int err;
	uint32_t rlen;
	struct nlmsghdr	*nlh;
	struct tgt_event *ev;

	while (skb->len >= NLMSG_SPACE(0)) {
		nlh = (struct nlmsghdr *) skb->data;
		if (nlh->nlmsg_len < sizeof(*nlh) || skb->len < nlh->nlmsg_len)
			return 0;
		ev = NLMSG_DATA(nlh);
		rlen = NLMSG_ALIGN(nlh->nlmsg_len);
		if (rlen > skb->len)
			rlen = skb->len;
		err = event_recv_msg(skb, nlh);

		eprintk("%d %d\n", nlh->nlmsg_type, err);
		/*
		 * TODO for passthru commands the lower level should
		 * probably handle the result or we should modify this
		 */
		if (nlh->nlmsg_type != TGT_UEVENT_CMD_RES &&
		    nlh->nlmsg_type != TGT_UEVENT_TARGET_PASSTHRU) {
			ev->k.event_res.err = err;
			send_event_res(NETLINK_CREDS(skb)->pid,
				       TGT_KEVENT_RESPONSE,
				       ev, sizeof(*ev));
		}
		skb_pull(skb, rlen);
	}
	return 0;
}

static void event_recv(struct sock *sk, int length)
{
	struct sk_buff *skb;

	while ((skb = skb_dequeue(&sk->sk_receive_queue))) {
		if (event_recv_skb(skb) && skb->len)
			skb_queue_head(&sk->sk_receive_queue, skb);
		else
			kfree_skb(skb);
	}
}

static void __exit tgt_exit(void)
{
	if (nls)
		sock_release(nls->sk_socket);

	tgt_sysfs_exit();
}

static int __init tgt_init(void)
{
	int i, err = -ENOMEM;

	spin_lock_init(&all_targets_lock);
	spin_lock_init(&cmd_hash_lock);
	spin_lock_init(&target_tmpl_lock);
	spin_lock_init(&device_tmpl_lock);

	tgt_protocol_init();

	err = tgt_sysfs_init();
	if (err)
		return err;

	nls = netlink_kernel_create(NETLINK_TGT, 1, event_recv, THIS_MODULE);
	if (!nls)
		goto out;

	for (i = 0; i < ARRAY_SIZE(cmd_hash); i++)
		INIT_LIST_HEAD(&cmd_hash[i]);

	return 0;
out:
	tgt_exit();
	return err;
}

module_init(tgt_init);
module_exit(tgt_exit);
