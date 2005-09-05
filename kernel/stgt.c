/*
 * SCSI Targets Framework
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
#include <net/tcp.h>
#include <scsi/scsi.h>

#include <stgt.h>
#include <stgt_target.h>
#include <stgt_device.h>
#include <stgt_if.h>
#include <tgt_protocol.h>

#define DEBUG_STGT

#define eprintk(fmt, args...)					\
do {								\
	printk("%s(%d) " fmt, __FUNCTION__, __LINE__, args);	\
} while (0)

#ifdef DEBUG_STGT
#define dprintk eprintk
#else
#define dprintk(fmt, args...)
#endif

#define assert(p) do {						\
	if (!(p)) {						\
		printk(KERN_CRIT "BUG at %s:%d assert(%s)\n",	\
		       __FILE__, __LINE__, #p);			\
		dump_stack();					\
		BUG();						\
	}							\
} while (0)

MODULE_LICENSE("GPL");

static spinlock_t all_targets_lock;
static LIST_HEAD(all_targets);

static spinlock_t target_tmpl_lock;
static LIST_HEAD(target_tmpl_list);

static spinlock_t device_tmpl_lock;
static LIST_HEAD(device_tmpl_list);

static void session_init_handler(void *data);
static spinlock_t atomic_sessions_lock;
static LIST_HEAD(atomic_sessions);
static DECLARE_WORK(atomic_session_work, session_init_handler,
		    &atomic_sessions);

static int daemon_pid;
static struct sock *nls;

static kmem_cache_t *cmnd_slab, *work_slab;

/* TODO: lock per session */
static spinlock_t cmnd_hash_lock;
#define STGT_HASH_ORDER		8
#define	cmnd_hashfn(key)	hash_long((key), STGT_HASH_ORDER)
static struct list_head cmnd_hash[1 << STGT_HASH_ORDER];

struct atomic_session_args {
	struct stgt_session *session;
	void (*done) (void *, struct stgt_session *);
	int max_cmnds;
	void *arg;
	struct list_head list;
};

struct stgt_work {
	void (*fn) (void *);
	void *arg;
	mempool_t *pool;
	struct list_head list;
};

static struct stgt_work * stgt_init_work(struct stgt_session *session,
					 void (*fn)(void *), void *arg)
{
	struct stgt_work *work;
	mempool_t *pool = session->work_pool;

	work = mempool_alloc(pool, GFP_ATOMIC);
	if (!work)
		return NULL;

	work->fn = fn;
	work->arg = arg;
	work->pool = pool;

	return work;
}

static void stgt_worker(void *data)
{
	struct stgt_target *target = (struct stgt_target *) data;
	struct stgt_work *work = NULL;
	unsigned long flags;

	spin_lock_irqsave(&target->lock, flags);
	if (!list_empty(&target->work_list)) {
		work = list_entry(target->work_list.next, struct stgt_work, list);
		list_del(&work->list);
	}
	spin_unlock_irqrestore(&target->lock, flags);

	if (work) {
		work->fn(work->arg);
		mempool_free(work, work->pool);
	}

	return;
}

static void stgt_queue_work(struct stgt_target *target, struct stgt_work *work)
{
	unsigned long flags;

	spin_lock_irqsave(&target->lock, flags);
	list_add_tail(&work->list, &target->work_list);
	spin_unlock_irqrestore(&target->lock, flags);

	schedule_work(&target->work);
}

struct target_type_internal {
	struct list_head list;
	struct stgt_target_template *stt;
	struct tgt_protocol *proto;
};

static struct target_type_internal *target_template_get(const char *name)
{
	unsigned long flags;
	struct target_type_internal *ti;

	spin_lock_irqsave(&target_tmpl_lock, flags);

	list_for_each_entry(ti, &target_tmpl_list, list)
		if (!strcmp(name, ti->stt->name)) {
			if (!try_module_get(ti->stt->module))
				ti = NULL;
			spin_unlock_irqrestore(&target_tmpl_lock, flags);
			return ti;
		}

	spin_unlock_irqrestore(&target_tmpl_lock, flags);

	return NULL;
}

static void target_template_put(struct stgt_target_template *stt)
{
	module_put(stt->module);
}

int stgt_target_template_register(struct stgt_target_template *stt)
{
	unsigned long flags;
	struct target_type_internal *ti;

	ti = kmalloc(sizeof(*ti), GFP_KERNEL);
	if (!ti)
		return -ENOMEM;
	memset(ti, 0, sizeof(*ti));
	INIT_LIST_HEAD(&ti->list);
	ti->stt = stt;

	ti->proto = tgt_protocol_get(stt->protocol);
	if (!ti->proto) {
		eprintk("Could not find %s protocol\n", stt->protocol);
		kfree(ti);
		return -EINVAL;
	}

	spin_lock_irqsave(&target_tmpl_lock, flags);
	list_add_tail(&ti->list, &target_tmpl_list);
	spin_unlock_irqrestore(&target_tmpl_lock, flags);

	return 0;
}
EXPORT_SYMBOL_GPL(stgt_target_template_register);

void stgt_target_template_unregister(struct stgt_target_template *stt)
{
	unsigned long flags;
	struct target_type_internal *ti;

	spin_lock_irqsave(&target_tmpl_lock, flags);

	list_for_each_entry(ti, &target_tmpl_list, list)
		if (ti->stt == stt) {
			list_del(&ti->list);
			tgt_protocol_put(ti->proto);
			kfree(ti);
			break;
		}

	spin_unlock_irqrestore(&target_tmpl_lock, flags);
}
EXPORT_SYMBOL_GPL(stgt_target_template_unregister);

static struct stgt_target *target_find(int tid)
{
	struct stgt_target *target;

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

struct stgt_target *stgt_target_create(char *target_type, int queued_cmnds)
{
	static int target_id;
	struct stgt_target *target;
	struct target_type_internal *tti;

	if (!daemon_pid) {
		eprintk("%s\n", "Run the user-space daemon first!");
		return NULL;
	}

	target = kmalloc(sizeof(*target), GFP_KERNEL);
	if (!target)
		return NULL;
	dprintk("%p\n", target);
	memset(target, 0, sizeof(*target));

	tti = target_template_get(target_type);
	if (!tti)
		goto free_target;

	target->stt = tti->stt;
	target->proto = tti->proto;
	target->tid = target_id++;
	spin_lock_init(&target->lock);

	INIT_LIST_HEAD(&target->session_list);
	INIT_LIST_HEAD(&target->device_list);
	INIT_LIST_HEAD(&target->work_list);

	INIT_WORK(&target->work, stgt_worker, target);
	target->queued_cmnds = queued_cmnds;

	if (stgt_sysfs_register_target(target))
		goto put_template;

	spin_lock(&all_targets_lock);
	list_add(&target->tlist, &all_targets);
	spin_unlock(&all_targets_lock);
	return target;

put_template:
	target_template_put(target->stt);
free_target:
	kfree(target);
	return NULL;
}
EXPORT_SYMBOL(stgt_target_create);

int stgt_target_destroy(struct stgt_target *target)
{
	dprintk("%p\n", target);

	spin_lock(&all_targets_lock);
	list_del(&target->tlist);
	spin_unlock(&all_targets_lock);

	target_template_put(target->stt);
	stgt_sysfs_unregister_target(target);

	return 0;
}
EXPORT_SYMBOL(stgt_target_destroy);

static int session_init(struct stgt_session *session, int max_cmnds)
{
	struct stgt_target *target = session->target;
	unsigned long flags;

	session->cmnd_pool = mempool_create(max_cmnds, mempool_alloc_slab,
					    mempool_free_slab, cmnd_slab);
	if (!session->cmnd_pool)
		goto out;

	session->work_pool = mempool_create(max_cmnds, mempool_alloc_slab,
					    mempool_free_slab, work_slab);
	if (!session->work_pool)
		goto out;

	spin_lock_irqsave(&target->lock, flags);
	list_add(&session->slist, &target->session_list);
	spin_unlock_irqrestore(&target->lock, flags);

	return 0;
out:
	if (session->cmnd_pool)
		mempool_destroy(session->cmnd_pool);

	if (session->work_pool)
		mempool_destroy(session->work_pool);

	return -ENOMEM;
}

static void session_init_handler(void *data)
{
	struct list_head *head = (struct list_head *) data;
	struct atomic_session_args *ssa = NULL;
	unsigned long flags;
	int err;

	spin_lock_irqsave(&atomic_sessions_lock, flags);
	if (!list_empty(&atomic_sessions)) {
		ssa = list_entry(head->next, struct atomic_session_args, list);
		list_del(&ssa->list);
	}
	spin_unlock_irqrestore(&atomic_sessions_lock, flags);

	if (!ssa)
		return;

	err = session_init(ssa->session, ssa->max_cmnds);
	if (err)
		kfree(ssa->session);

	ssa->done(ssa->arg, err ? NULL : ssa->session);

	kfree(ssa);
}

static int session_atomic_init(struct stgt_session *session,
			       int max_cmnds,
			       void (*done) (void *, struct stgt_session *),
			       int *arg)
{
	struct atomic_session_args *ssa;
	unsigned long flags;

	ssa = kmalloc(sizeof(*ssa), GFP_ATOMIC);
	if (!ssa)
		return -ENOMEM;

	ssa->session = session;
	ssa->max_cmnds = max_cmnds;
	ssa->arg = arg;

	spin_lock_irqsave(&atomic_sessions_lock, flags);
	list_add(&ssa->list, &atomic_sessions);
	spin_unlock_irqrestore(&atomic_sessions_lock, flags);

	schedule_work(&atomic_session_work);

	return 0;
}

struct stgt_session *
stgt_session_create(struct stgt_target *target,
		    int max_cmnds,
		    void (*done)(void *, struct stgt_session *),
		    void *arg)
{
	struct stgt_session *session;

	if (!target) {
		eprintk("%s\n", "Null target pointer!");
		return NULL;
	}

	if (done && !arg) {
		eprintk("%s\n", "Need arg !");
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
		if (session_atomic_init(session, max_cmnds, done, arg) < 0)
			goto out;

		return session;
	}

	if (session_init(session, max_cmnds) < 0)
		goto out;

	return session;

out:
	kfree(session);
	return NULL;
}
EXPORT_SYMBOL(stgt_session_create);

int stgt_session_destroy(struct stgt_session *session)
{
	mempool_destroy(session->cmnd_pool);
	mempool_destroy(session->work_pool);
	kfree(session);

	return 0;
}
EXPORT_SYMBOL(stgt_session_destroy);

struct device_type_internal {
	struct stgt_device_template *sdt;
	struct list_head list;
};

static struct stgt_device_template *device_template_get(const char *name)
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

static void device_template_put(struct stgt_device_template *sdt)
{
	module_put(sdt->module);
}

int stgt_device_template_register(struct stgt_device_template *sdt)
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
EXPORT_SYMBOL_GPL(stgt_device_template_register);

void stgt_device_template_unregister(struct stgt_device_template *sdt)
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
EXPORT_SYMBOL_GPL(stgt_device_template_unregister);

/*
 * TODO: use a hash or any better alg/ds
 */
static struct stgt_device *
stgt_device_find_nolock(struct stgt_target *target, uint64_t dev_id)
{
	struct stgt_device *device;

	list_for_each_entry(device, &target->device_list, dlist)
		if (device->dev_id == dev_id)
			return device;

	return NULL;
}

static struct stgt_device *
stgt_device_find(struct stgt_target *target, uint64_t dev_id)
{
	static struct stgt_device *device;
	unsigned long flags;

	spin_lock_irqsave(&target->lock, flags);
	device = stgt_device_find_nolock(target, dev_id);
	spin_unlock_irqrestore(&target->lock, flags);

	return device;
}

static int stgt_device_create(int tid, uint64_t dev_id, char *device_type,
			      char *path, unsigned long dflags)
{
	struct stgt_target *target;
	struct stgt_device *device;
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

	device->sdt = device_template_get(device_type);
	if (!device->sdt) {
		eprintk("Could not get devive type %s\n", device_type);
		goto free_path;
	}

	device->sdt_data = kmalloc(sizeof(device->sdt->priv_data_size),
				   GFP_KERNEL);
	if (!device->sdt_data)
		goto put_template;

	if (device->sdt->create)
		if (device->sdt->create(device))
			goto free_priv_sdt_data;

	if (stgt_sysfs_register_device(device))
		goto sdt_destroy;

	spin_lock_irqsave(&target->lock, flags);
	list_add(&device->dlist, &target->device_list);
	spin_unlock_irqrestore(&target->lock, flags);

	return 0;

sdt_destroy:
	if (device->sdt->destroy)
		device->sdt->destroy(device);
free_priv_sdt_data:
	kfree(device->sdt_data);
put_template:
	device_template_put(device->sdt);
free_path:
	kfree(device->path);
free_device:
	kfree(device);
	return -EINVAL;
}

static int stgt_device_destroy(int tid, uint64_t dev_id)
{
	struct stgt_device *device;
	struct stgt_target *target;
	unsigned long flags;

	target = target_find(tid);
	if (!target)
		return -ENOENT;

	spin_lock_irqsave(&target->lock, flags);
	device = stgt_device_find_nolock(target, dev_id);
	spin_unlock_irqrestore(&target->lock, flags);
	if (!device)
		return -EINVAL;

	list_del(&device->dlist);
	if (device->sdt->destroy)
		device->sdt->destroy(device);

	device_template_put(device->sdt);
	stgt_sysfs_unregister_device(device);

	return 0;
}

struct stgt_cmnd *stgt_cmnd_create(struct stgt_session *session)
{
	static uint64_t cid = 0;
	struct stgt_cmnd *cmnd;
	unsigned long flags;

	dprintk("%p %llu\n", session, cid);
	cmnd = mempool_alloc(session->cmnd_pool, GFP_ATOMIC);
	assert(cmnd);
	memset(cmnd, 0, sizeof(*cmnd));
	cmnd->session = session;
	cmnd->cid = cid++;
	INIT_LIST_HEAD(&cmnd->clist);
	INIT_LIST_HEAD(&cmnd->hash_list);

	dprintk("%p %llu\n", session, cid);

	spin_lock_irqsave(&cmnd_hash_lock, flags);
	list_add_tail(&cmnd->hash_list, &cmnd_hash[cmnd_hashfn(cmnd->cid)]);
	spin_unlock_irqrestore(&cmnd_hash_lock, flags);

	return cmnd;
}
EXPORT_SYMBOL(stgt_cmnd_create);

void stgt_cmnd_destroy(struct stgt_cmnd *cmnd)
{
	unsigned long flags;
	int i;

	for (i = 0; i < cmnd->sg_count; i++)
		__free_page(cmnd->sg[i].page);
	kfree(cmnd->sg);

	spin_lock_irqsave(&cmnd_hash_lock, flags);
	list_del(&cmnd->hash_list);
	spin_unlock_irqrestore(&cmnd_hash_lock, flags);

	mempool_free(cmnd, cmnd->session->cmnd_pool);
}
EXPORT_SYMBOL(stgt_cmnd_destroy);

#define pgcnt(size, offset)	((((size) + ((offset) & ~PAGE_CACHE_MASK)) + PAGE_CACHE_SIZE - 1) >> PAGE_CACHE_SHIFT)

void __stgt_alloc_buffer(struct stgt_cmnd *cmnd)
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
EXPORT_SYMBOL(__stgt_alloc_buffer);

static void stgt_alloc_buffer(void *data)
{
	struct stgt_cmnd *cmnd = data;

	dprintk("%x %llu %u\n", cmnd->scb[0], cmnd->offset, cmnd->bufflen);
	__stgt_alloc_buffer(cmnd);

	if (cmnd->done) {
		void (*done)(struct stgt_cmnd *) = cmnd->done;
		cmnd->done = NULL;
		done(cmnd);
	}
}

void stgt_cmnd_alloc_buffer(struct stgt_cmnd *cmnd, void (*done)(struct stgt_cmnd *))
{
	struct tgt_protocol *proto = cmnd->session->target->proto;

	assert(list_empty(&cmnd->clist));

	proto->init_cmnd_buffer(cmnd);

	if (done) {
		struct stgt_session *session = cmnd->session;
		struct stgt_work *work;

		work = stgt_init_work(session, stgt_alloc_buffer, cmnd);
		stgt_queue_work(session->target, work);
		return;
	};

	stgt_alloc_buffer(cmnd);
}
EXPORT_SYMBOL(stgt_cmnd_alloc_buffer);

static int uspace_cmnd_send(struct stgt_cmnd *cmnd)
{
	struct sk_buff *skb;
	struct nlmsghdr *nlh;
	struct stgt_event *ev;
	char *pdu;
	int len;

	len = NLMSG_SPACE(sizeof(*ev) + sizeof(cmnd->scb));
	skb = alloc_skb(NLMSG_SPACE(len), GFP_KERNEL);
	if (!skb)
		return -ENOMEM;

	dprintk("%d %Zd %Zd\n", len, sizeof(*ev), sizeof(cmnd->scb));
	nlh = __nlmsg_put(skb, daemon_pid, 0,
			  STGT_KEVENT_SCSI_CMND_REQ, len - sizeof(*nlh), 0);
	ev = NLMSG_DATA(nlh);
	memset(ev, 0, sizeof(*ev));

	pdu = (char *) ev + sizeof(*ev);
	ev->k.cmnd_req.tid = cmnd->session->target->tid;
	ev->k.cmnd_req.dev_id = cmnd->dev_id;
	ev->k.cmnd_req.cid = cmnd->cid;

	memcpy(pdu, cmnd->scb, sizeof(cmnd->scb));

	return netlink_unicast(nls, skb, daemon_pid, 0);
}

static void cmnd_done(struct stgt_cmnd *cmnd)
{
	void (*done)(struct stgt_cmnd *);

	done = cmnd->done;
	cmnd->done = NULL;
	done(cmnd);
}

static void kspace_cmnd_done(struct stgt_cmnd *cmnd, int result)
{
	struct stgt_target *target = cmnd->session->target;
	struct tgt_protocol *proto = target->proto;

	proto->cmnd_done(cmnd, result);
	cmnd_done(cmnd);
}

static void uspace_cmnd_done(struct stgt_cmnd *cmnd, char *data,
			     int result, uint32_t len)
{
	int i;
	assert(cmnd->done);

	dprintk("%x %u\n", cmnd->scb[0], len);

	if (len) {
		cmnd->bufflen = len;
		cmnd->offset = 0;
		__stgt_alloc_buffer(cmnd);

		for (i = 0; i < cmnd->sg_count; i++) {
			uint32_t copy = min_t(uint32_t, len, PAGE_CACHE_SIZE);
			char *p = data;

			memcpy(page_address(cmnd->sg[i].page), p, copy);
			p += copy;
			len -= copy;
		}
	}

	cmnd->result = result;
	cmnd_done(cmnd);
}

static void queuecommand(void *data)
{
	int err = 0;
	struct stgt_cmnd *cmnd = data;
	struct stgt_target *target = cmnd->session->target;
	struct stgt_device *device;

	dprintk("%x\n", cmnd->scb[0]);

	/* Should we do this earlier? */
	device = stgt_device_find(target, cmnd->dev_id);
	if (device)
		dprintk("found %llu\n", cmnd->dev_id);

	if (cmnd->rw == READ || cmnd->rw == WRITE)
		err = device->sdt->queue_cmnd(device, cmnd);
	else {
		err = uspace_cmnd_send(cmnd);
		if (err >= 0)
			/* sent to userspace */
			return;
	}

	if (unlikely(err))
		eprintk("failed cmnd %llu %u %d %d\n",
			cmnd->cid, cmnd->scb[0], err, cmnd->rw);
	kspace_cmnd_done(cmnd, err);
}

int stgt_cmnd_queue(struct stgt_cmnd *cmnd, uint8_t *id_buff, int buff_size,
		    void (*done)(struct stgt_cmnd *))
{
	struct stgt_work *work;
	struct stgt_session *session = cmnd->session;
	struct tgt_protocol *proto = session->target->proto;

	dprintk("%p %x\n", cmnd, cmnd->scb[0]);

	assert(!cmnd->done);
	cmnd->done = done;
	if (!done) {
		eprintk("%s\n", "Null done function!");
		return -EINVAL;
	}

	work = stgt_init_work(session, queuecommand, cmnd);
	if (!work)
		return -ENOMEM;

	proto->prep_cmnd(cmnd, id_buff, buff_size);
	stgt_queue_work(session->target, work);

	return 0;
}
EXPORT_SYMBOL(stgt_cmnd_queue);

static struct stgt_cmnd *find_cmnd_by_id(uint64_t cid)
{
	struct list_head *head;
	struct stgt_cmnd *cmnd;
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
	struct stgt_event *ev = NLMSG_DATA(nlh);
	struct stgt_cmnd *cmnd;

	daemon_pid  = NETLINK_CREDS(skb)->pid;

	dprintk("%d %d\n", daemon_pid, nlh->nlmsg_type);

	switch (nlh->nlmsg_type) {
	case STGT_UEVENT_START:
		dprintk("start %d\n", daemon_pid);
		break;
	case STGT_UEVENT_DEVICE_CREATE:
		if (nlh->nlmsg_len <= NLMSG_SPACE(sizeof(*ev))) {
			err = -EINVAL;
			break;
		}
		err = stgt_device_create(ev->u.c_device.tid,
					 ev->u.c_device.dev_id,
					 ev->u.c_device.type,
					 (char *) ev + sizeof(*ev),
					 ev->u.c_device.flags);
		break;
	case STGT_UEVENT_DEVICE_DESTROY:
		err = stgt_device_destroy(ev->u.d_device.tid,
					  ev->u.d_device.dev_id);
		break;
	case STGT_UEVENT_SCSI_CMND_RES:
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
	struct stgt_event *ev;

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
		if (nlh->nlmsg_type != STGT_UEVENT_SCSI_CMND_RES)
			send_event_res(NETLINK_CREDS(skb)->pid,
				       STGT_KEVENT_RESPONSE,
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

static void __exit stgt_exit(void)
{
	if (cmnd_slab)
		kmem_cache_destroy(cmnd_slab);

	if (work_slab)
		kmem_cache_destroy(work_slab);

	if (nls)
		sock_release(nls->sk_socket);

	stgt_sysfs_exit();
}

static int __init stgt_init(void)
{
	int i, err = -ENOMEM;

	spin_lock_init(&all_targets_lock);
	spin_lock_init(&atomic_sessions_lock);
	spin_lock_init(&cmnd_hash_lock);
	spin_lock_init(&target_tmpl_lock);
	spin_lock_init(&device_tmpl_lock);

	tgt_protocol_init();

	err = stgt_sysfs_init();
	if (err)
		return err;

	cmnd_slab = kmem_cache_create("stgt_cmnd", sizeof(struct stgt_cmnd), 0,
				      SLAB_HWCACHE_ALIGN | SLAB_NO_REAP,
				      NULL, NULL);
	if (!cmnd_slab)
		goto out;

	work_slab = kmem_cache_create("stgt_work", sizeof(struct stgt_work), 0,
				      SLAB_HWCACHE_ALIGN | SLAB_NO_REAP,
				      NULL, NULL);
	if (!work_slab)
		goto out;

	nls = netlink_kernel_create(NETLINK_STGT, event_recv);
	if (!nls)
		goto out;

	for (i = 0; i < ARRAY_SIZE(cmnd_hash); i++)
		INIT_LIST_HEAD(&cmnd_hash[i]);

	return 0;
out:
	stgt_exit();
	return err;
}

module_init(stgt_init);
module_exit(stgt_exit);
