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

static int daemon_pid;
static struct sock *nls;

static kmem_cache_t *cmnd_slab;

/* TODO: lock per session */
static spinlock_t cmnd_hash_lock;
#define TGT_HASH_ORDER		8
#define	cmnd_hashfn(key)	hash_long((key), TGT_HASH_ORDER)
static struct list_head cmnd_hash[1 << TGT_HASH_ORDER];

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

	ti = kmalloc(sizeof(*ti), GFP_KERNEL);
	if (!ti)
		return -ENOMEM;
	memset(ti, 0, sizeof(*ti));
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

struct tgt_target *tgt_target_create(char *target_type, int queued_cmnds)
{
	char name[16];
	static int target_id;
	struct tgt_target *target;
	struct target_type_internal *ti;

	if (!daemon_pid) {
		eprintk("%s\n", "Run the user-space daemon first!");
		return NULL;
	}

	target = kmalloc(sizeof(*target), GFP_KERNEL);
	if (!target)
		return NULL;
	memset(target, 0, sizeof(*target));

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

	target->queued_cmnds = queued_cmnds;

	snprintf(name, sizeof(name), "tgtd%d", target->tid);
	target->twq = create_workqueue(name);
	if (!target->twq)
		goto put_template;

	target->tt_data = kmalloc(target->tt->priv_data_size, GFP_KERNEL);
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

static int session_init(struct tgt_session *session, int max_cmnds)
{
	struct tgt_target *target = session->target;
	unsigned long flags;

	session->cmnd_pool = mempool_create(max_cmnds, mempool_alloc_slab,
					    mempool_free_slab, cmnd_slab);
	if (!session->cmnd_pool)
		goto out;

	spin_lock_irqsave(&target->lock, flags);
	list_add(&session->slist, &target->session_list);
	spin_unlock_irqrestore(&target->lock, flags);

	return 0;
out:
	if (session->cmnd_pool)
		mempool_destroy(session->cmnd_pool);

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
		   int max_cmnds,
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

	dprintk("%p %d\n", target, max_cmnds);

	session = kmalloc(sizeof(*session), done ? GFP_ATOMIC : GFP_KERNEL);
	if (!session)
		return NULL;
	memset(session, 0, sizeof(*session));
	session->target = target;
	INIT_LIST_HEAD(&session->slist);

	if (done) {
		async = kmalloc(sizeof(*async), GFP_ATOMIC);
		if (!async)
			goto out;

		async->session = session;
		async->cmds = max_cmnds;
		async->done = done;
		async->arg = arg;

		INIT_WORK(&async->work, session_async_create, async);
		queue_work(session->target->twq, &async->work);
		return session;
	}

	if (session_init(session, max_cmnds) < 0)
		goto out;

	return session;

out:
	kfree(session);
	return NULL;
}
EXPORT_SYMBOL_GPL(tgt_session_create);

int tgt_session_destroy(struct tgt_session *session)
{
	mempool_destroy(session->cmnd_pool);
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

	ti = kmalloc(sizeof(*ti), GFP_KERNEL);
	if (!ti)
		return -ENOMEM;
	memset(ti, 0, sizeof(*ti));
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

static struct tgt_device *
tgt_device_find(struct tgt_target *target, uint64_t dev_id)
{
	static struct tgt_device *device;
	unsigned long flags;

	spin_lock_irqsave(&target->lock, flags);
	device = tgt_device_find_nolock(target, dev_id);
	spin_unlock_irqrestore(&target->lock, flags);

	return device;
}

static int tgt_device_create(int tid, uint64_t dev_id, char *device_type,
			      char *path, unsigned long dflags)
{
	struct tgt_target *target;
	struct tgt_device *device;
	unsigned long flags;

	dprintk("%d %llu %s %s\n", tid, dev_id, device_type, path);

	target = target_find(tid);
	if (!target)
		return -EINVAL;

	device = kmalloc(sizeof(*device), GFP_KERNEL);
	if (!device)
		return -ENOMEM;

	memset(device, 0, sizeof(*device));
	device->dev_id = dev_id;
	device->target = target;
	device->path = kstrdup(path, GFP_KERNEL);
	if (!device->path)
		goto free_device;

	device->dt = device_template_get(device_type);
	if (!device->dt) {
		eprintk("Could not get devive type %s\n", device_type);
		goto free_path;
	}

	device->dt_data = kmalloc(device->dt->priv_data_size,
				  GFP_KERNEL);
	if (!device->dt_data)
		goto put_template;

	if (device->dt->create)
		if (device->dt->create(device))
			goto free_priv_dt_data;

	if (tgt_sysfs_register_device(device))
		goto dt_destroy;

	spin_lock_irqsave(&target->lock, flags);
	list_add(&device->dlist, &target->device_list);
	spin_unlock_irqrestore(&target->lock, flags);

	return 0;

dt_destroy:
	if (device->dt->destroy)
		device->dt->destroy(device);
free_priv_dt_data:
	kfree(device->dt_data);
put_template:
	device_template_put(device->dt);
free_path:
	kfree(device->path);
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

	device_template_put(device->dt);
	tgt_sysfs_unregister_device(device);

	return 0;
}

struct tgt_cmnd *tgt_cmnd_create(struct tgt_session *session,
				   uint8_t *proto_data,
				   uint8_t *id_buff, int buff_size)
{
	struct tgt_protocol *proto = session->target->proto;
	struct tgt_cmnd *cmnd;
	void *pcmnd_data;
	unsigned long flags;

	/*
	 * slab in tgt_protocol structure like struct proto (in net/sock.h) ?
	 * However, how can we guarantee the specified number of commands ?
	 */
	pcmnd_data = kmalloc(proto->priv_cmd_data_size, GFP_ATOMIC);
	if (!pcmnd_data)
		return NULL;

	cmnd = mempool_alloc(session->cmnd_pool, GFP_ATOMIC);
	BUG_ON(!cmnd);
	memset(cmnd, 0, sizeof(*cmnd));
	cmnd->tgt_protocol_private = pcmnd_data;
	cmnd->session = session;
	cmnd->cid = (uint64_t) (unsigned long) cmnd;
	INIT_LIST_HEAD(&cmnd->clist);
	INIT_LIST_HEAD(&cmnd->hash_list);

	dprintk("%p %llu\n", session, cmnd->cid);

	proto->init_cmnd(cmnd, proto_data, id_buff, buff_size);

	spin_lock_irqsave(&cmnd_hash_lock, flags);
	list_add_tail(&cmnd->hash_list, &cmnd_hash[cmnd_hashfn(cmnd->cid)]);
	spin_unlock_irqrestore(&cmnd_hash_lock, flags);

	return cmnd;
}
EXPORT_SYMBOL_GPL(tgt_cmnd_create);

void tgt_cmnd_destroy(struct tgt_cmnd *cmnd)
{
	unsigned long flags;
	int i;

	kfree(cmnd->tgt_protocol_private);

	for (i = 0; i < cmnd->sg_count; i++)
		__free_page(cmnd->sg[i].page);
	kfree(cmnd->sg);

	spin_lock_irqsave(&cmnd_hash_lock, flags);
	list_del(&cmnd->hash_list);
	spin_unlock_irqrestore(&cmnd_hash_lock, flags);

	mempool_free(cmnd, cmnd->session->cmnd_pool);
}
EXPORT_SYMBOL_GPL(tgt_cmnd_destroy);

#define pgcnt(size, offset)	((((size) + ((offset) & ~PAGE_CACHE_MASK)) + PAGE_CACHE_SIZE - 1) >> PAGE_CACHE_SHIFT)

void __tgt_alloc_buffer(struct tgt_cmnd *cmnd)
{
	uint64_t offset = cmnd->offset;
	uint32_t len = cmnd->bufflen;
	int i;

	cmnd->sg_count = pgcnt(len, offset);
	offset &= ~PAGE_CACHE_MASK;

	cmnd->sg = kmalloc(cmnd->sg_count * sizeof(struct scatterlist),
			   GFP_KERNEL | __GFP_NOFAIL);

	for (i = 0; i < cmnd->sg_count; i++) {
		struct scatterlist *sg = &cmnd->sg[i];

		sg->page = alloc_page(GFP_KERNEL | __GFP_NOFAIL);
		sg->offset = offset;
		sg->length = min_t(uint32_t, PAGE_CACHE_SIZE - offset, len);

		offset = 0;
		len -= sg->length;
	}
}

static void tgt_alloc_buffer(void *data)
{
	struct tgt_cmnd *cmnd = data;

	__tgt_alloc_buffer(cmnd);

	if (cmnd->done) {
		void (*done)(struct tgt_cmnd *) = cmnd->done;
		cmnd->done = NULL;
		done(cmnd);
	}
}

void tgt_cmnd_alloc_buffer(struct tgt_cmnd *cmnd, void (*done)(struct tgt_cmnd *))
{
	struct tgt_protocol *proto = cmnd->session->target->proto;

	BUG_ON(!list_empty(&cmnd->clist));

	proto->init_cmnd_buffer(cmnd);

	if (done) {
		struct tgt_session *session = cmnd->session;

		INIT_WORK(&cmnd->work, tgt_alloc_buffer, cmnd);
		cmnd->done = done;
		queue_work(session->target->twq, &cmnd->work);
		return;
	}

	tgt_alloc_buffer(cmnd);
}
EXPORT_SYMBOL_GPL(tgt_cmnd_alloc_buffer);

static int uspace_cmnd_send(struct tgt_cmnd *cmnd)
{
	struct tgt_protocol *proto = cmnd->session->target->proto;
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
	nlh = __nlmsg_put(skb, daemon_pid, 0,
			  TGT_KEVENT_CMND_REQ, len - sizeof(*nlh), 0);
	ev = NLMSG_DATA(nlh);
	memset(ev, 0, sizeof(*ev));

	pdu = (char *) ev + sizeof(*ev);
	ev->k.cmnd_req.tid = cmnd->session->target->tid;
	ev->k.cmnd_req.dev_id = cmnd->dev_id;
	ev->k.cmnd_req.cid = cmnd->cid;

	proto->build_uspace_pdu(cmnd, pdu);

	return netlink_unicast(nls, skb, daemon_pid, 0);
}

static void cmnd_done(struct tgt_cmnd *cmnd, int result)
{
	struct tgt_target *target = cmnd->session->target;
	struct tgt_protocol *proto = target->proto;
	void (*done)(struct tgt_cmnd *);

	proto->cmnd_done(cmnd, result);
	cmnd->result = result;

	done = cmnd->done;
	cmnd->done = NULL;
	done(cmnd);
}

static void uspace_cmnd_done(struct tgt_cmnd *cmnd, char *data,
			     int result, uint32_t len)
{
	int i;
	BUG_ON(!cmnd->done);

	if (len) {
		cmnd->bufflen = len;
		cmnd->offset = 0;
		__tgt_alloc_buffer(cmnd);

		for (i = 0; i < cmnd->sg_count; i++) {
			uint32_t copy = min_t(uint32_t, len, PAGE_CACHE_SIZE);
			char *dest, *p = data;

			dest = kmap_atomic(cmnd->sg[i].page, KM_SOFTIRQ0);
			memcpy(dest, p, copy);
			kunmap_atomic(dest, KM_SOFTIRQ0);

			p += copy;
			len -= copy;
		}
	}

	cmnd_done(cmnd, result);
}

static void queuecommand(void *data)
{
	int err = 0;
	struct tgt_cmnd *cmnd = data;
	struct tgt_target *target = cmnd->session->target;
	struct tgt_device *device;

	/* Should we do this earlier? */
	device = tgt_device_find(target, cmnd->dev_id);
	if (device)
		dprintk("found %llu\n", cmnd->dev_id);

	if (cmnd->rw == READ || cmnd->rw == WRITE)
		err = device->dt->queue_cmnd(device, cmnd);
	else {
		err = uspace_cmnd_send(cmnd);
		if (err >= 0)
			/* sent to userspace */
			return;
	}

	/* kspace command failure or failed to send commands to space. */
	if (unlikely(err))
		eprintk("failed cmnd %llu %d %d\n", cmnd->cid, err, cmnd->rw);

	cmnd_done(cmnd, err);
}

int tgt_cmnd_queue(struct tgt_cmnd *cmnd, void (*done)(struct tgt_cmnd *))
{
	struct tgt_session *session = cmnd->session;

	BUG_ON(cmnd->done);
	BUG_ON(!done);

	cmnd->done = done;
	INIT_WORK(&cmnd->work, queuecommand, cmnd);
	queue_work(session->target->twq, &cmnd->work);

	return 0;
}
EXPORT_SYMBOL_GPL(tgt_cmnd_queue);

static struct tgt_cmnd *find_cmnd_by_id(uint64_t cid)
{
	struct list_head *head;
	struct tgt_cmnd *cmnd;
	unsigned long flags;

	head = &cmnd_hash[cmnd_hashfn(cid)];

	spin_lock_irqsave(&cmnd_hash_lock, flags);

	list_for_each_entry(cmnd, head, hash_list) {
		if (cmnd->cid == cid)
			goto found;
	}
	cmnd = NULL;
found:
	spin_unlock_irqrestore(&cmnd_hash_lock, flags);

	return cmnd;
}

static int event_recv_msg(struct sk_buff *skb, struct nlmsghdr *nlh)
{
	int err = 0;
	struct tgt_event *ev = NLMSG_DATA(nlh);
	struct tgt_cmnd *cmnd;
	struct tgt_target *target;

	daemon_pid  = NETLINK_CREDS(skb)->pid;

	dprintk("%d %d\n", daemon_pid, nlh->nlmsg_type);

	switch (nlh->nlmsg_type) {
	case TGT_UEVENT_START:
		dprintk("start %d\n", daemon_pid);
		break;
	case TGT_UEVENT_TARGET_CREATE:
		target = tgt_target_create(ev->u.c_target.type,
					   ev->u.c_target.nr_cmnds);
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
	case TGT_UEVENT_DEVICE_CREATE:
		if (nlh->nlmsg_len <= NLMSG_SPACE(sizeof(*ev))) {
			err = -EINVAL;
			break;
		}
		err = tgt_device_create(ev->u.c_device.tid,
					ev->u.c_device.dev_id,
					ev->u.c_device.type,
					(char *) ev + sizeof(*ev),
					ev->u.c_device.flags);
		break;
	case TGT_UEVENT_DEVICE_DESTROY:
		err = tgt_device_destroy(ev->u.d_device.tid,
					 ev->u.d_device.dev_id);
		break;
	case TGT_UEVENT_CMND_RES:
		cmnd = find_cmnd_by_id(ev->u.cmnd_res.cid);
		if (cmnd)
			uspace_cmnd_done(cmnd, (char *) ev + sizeof(*ev),
					 ev->u.cmnd_res.result,
					 ev->u.cmnd_res.len);
		else {
			eprintk("cannot found %llu\n", ev->u.cmnd_res.cid);
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
		ev->k.event_res.err = err;
		if (nlh->nlmsg_type != TGT_UEVENT_CMND_RES)
			send_event_res(NETLINK_CREDS(skb)->pid,
				       TGT_KEVENT_RESPONSE,
				       ev, sizeof(*ev));
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
	if (cmnd_slab)
		kmem_cache_destroy(cmnd_slab);

	if (nls)
		sock_release(nls->sk_socket);

	tgt_sysfs_exit();
}

static int __init tgt_init(void)
{
	int i, err = -ENOMEM;

	spin_lock_init(&all_targets_lock);
	spin_lock_init(&cmnd_hash_lock);
	spin_lock_init(&target_tmpl_lock);
	spin_lock_init(&device_tmpl_lock);

	tgt_protocol_init();

	err = tgt_sysfs_init();
	if (err)
		return err;

	cmnd_slab = kmem_cache_create("tgt_cmnd", sizeof(struct tgt_cmnd), 0,
				      SLAB_HWCACHE_ALIGN | SLAB_NO_REAP,
				      NULL, NULL);
	if (!cmnd_slab)
		goto out;

	nls = netlink_kernel_create(NETLINK_TGT, event_recv);
	if (!nls)
		goto out;

	for (i = 0; i < ARRAY_SIZE(cmnd_hash); i++)
		INIT_LIST_HEAD(&cmnd_hash[i]);

	return 0;
out:
	tgt_exit();
	return err;
}

module_init(tgt_init);
module_exit(tgt_exit);
