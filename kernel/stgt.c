/*
 * SCSI Targets Framework
 *
 * (C) 2005 FUJITA Tomonori <tomof@acm.org>
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
#include <stgt_if.h>

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

struct stgt_target *stgt_target_create(void)
{
	struct stgt_target *target;

	if (!daemon_pid) {
		eprintk("%s\n", "Run the user-space daemon first!");
		return NULL;
	}

	target = kmalloc(sizeof(*target), GFP_KERNEL);
	if (!target)
		return NULL;

	dprintk("%p\n", target);

	memset(target, 0, sizeof(*target));
	spin_lock_init(&target->lock);

	INIT_LIST_HEAD(&target->session_list);
	INIT_LIST_HEAD(&target->lu_list);
	INIT_LIST_HEAD(&target->work_list);

	INIT_WORK(&target->work, stgt_worker, target);

	spin_lock(&all_targets_lock);
	list_add(&target->tlist, &all_targets);
	spin_unlock(&all_targets_lock);

	return target;
}
EXPORT_SYMBOL(stgt_target_create);

int stgt_target_destroy(struct stgt_target *target)
{
	spin_lock(&all_targets_lock);
	list_del(&target->tlist);
	spin_unlock(&all_targets_lock);

	kfree(target);

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

static void set_offset_and_length(uint8_t *scb, uint64_t *off, uint32_t *len)
{
	switch (scb[0]) {
	case READ_6:
	case WRITE_6:
		*off = ((scb[1] & 0x1f) << 16) + (scb[2] << 8) + scb[3];
		*len = scb[4];
		if (!*len)
			*len = 256;
		break;
	case READ_10:
	case WRITE_10:
	case WRITE_VERIFY:
		*off = be32_to_cpu(*(u32 *) &scb[2]);
		*len = (scb[7] << 8) + scb[8];
		break;
	case READ_16:
	case WRITE_16:
		*off = be64_to_cpu(*(u64 *)&scb[2]);
		*len = be32_to_cpu(*(u32 *)&scb[10]);
		break;
	default:
		break;
	}

	*off <<= 9;
	*len <<= 9;
}

#define pgcnt(size, offset)	((((size) + ((offset) & ~PAGE_CACHE_MASK)) + PAGE_CACHE_SIZE - 1) >> PAGE_CACHE_SHIFT)

static void __alloc_buffer(struct stgt_cmnd *cmnd, uint32_t len, uint64_t offset)
{
	int i;

	cmnd->sg_count = pgcnt(len, offset);
	cmnd->bufflen = len;
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

static void alloc_buffer(void *data)
{
	struct stgt_cmnd *cmnd = (struct stgt_cmnd *) data;
	uint32_t len = 0;
	uint64_t offset = 0;

	set_offset_and_length(cmnd->scb, &offset, &len);

	dprintk("%x %llu %u", cmnd->scb[0], offset, len);
	__alloc_buffer(cmnd, len, offset);

	if (cmnd->done) {
		void (*done)(struct stgt_cmnd *) = cmnd->done;
		cmnd->done = NULL;
		done(cmnd);
	}
}

void stgt_cmnd_alloc_buffer(struct stgt_cmnd *cmnd, void (*done)(struct stgt_cmnd *))
{
	assert(list_empty(&cmnd->clist));

	if (done) {
		struct stgt_work *work;
		struct stgt_session *session = cmnd->session;

		work = mempool_alloc(session->work_pool, GFP_ATOMIC);
		work->fn = alloc_buffer;
		work->arg = cmnd;
		work->pool = session->work_pool;
		stgt_queue_work(session->target, work);
		return;
	};

	alloc_buffer(cmnd);
}
EXPORT_SYMBOL(stgt_cmnd_alloc_buffer);

static int uspace_cmnd_send(struct stgt_cmnd *cmnd)
{
	struct sk_buff *skb;
	struct nlmsghdr *nlh;
	struct stgt_event *ev;
	char *pdu;
	int len = NLMSG_SPACE(sizeof(*ev) + sizeof(cmnd->scb));

	if (!(skb = alloc_skb(NLMSG_SPACE(len), GFP_KERNEL)))
		return -ENOMEM;

	dprintk("%d %Zd %Zd\n", len, sizeof(*ev), sizeof(cmnd->scb));
	nlh = __nlmsg_put(skb, daemon_pid, 0,
			  STGT_UEVENT_SCSI_CMND_REQ, len - sizeof(*nlh), 0);
	ev = NLMSG_DATA(nlh);
	memset(ev, 0, sizeof(*ev));

	pdu = (char *) ev + sizeof(*ev);
	ev->u.msg_scsi_cmnd.cid = cmnd->cid;

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

static void uspace_cmnd_done(struct stgt_cmnd *cmnd, char *data, uint32_t datasize)
{
	assert(cmnd->done);

	dprintk("%x %u\n", cmnd->scb[0], datasize);

	__alloc_buffer(cmnd, datasize, 0);
	/* FIXEM: multiple pages */
	memcpy(page_address(cmnd->sg[0].page), data, datasize);

	cmnd_done(cmnd);
}

static void virtual_disk_handler(void *data)
{
	struct stgt_cmnd *cmnd = (struct stgt_cmnd *) data;

	dprintk("%x\n", cmnd->scb[0]);

	switch (cmnd->scb[0]) {
	case READ_6:
	case READ_10:
	case READ_16:
	case WRITE_6:
	case WRITE_10:
	case WRITE_16:
	case WRITE_VERIFY:
	case RESERVE:
	case RELEASE:
	case RESERVE_10:
	case RELEASE_10:
		/* TODO */
		cmnd_done(cmnd);
		break;
	default:
		if (uspace_cmnd_send(cmnd) < 0)
			assert(0);
		break;
	}
}

int stgt_cmnd_queue(struct stgt_cmnd *cmnd, void (*done)(struct stgt_cmnd *))
{
	struct stgt_work *work;
	struct stgt_session *session = cmnd->session;

	dprintk("%p %x\n", cmnd, cmnd->scb[0]);

	assert(!cmnd->done);
	cmnd->done = done;
	if (!done) {
		eprintk("%s\n", "Null done function!");
		return -EINVAL;
	}

	work = mempool_alloc(session->work_pool, GFP_ATOMIC);
	work->fn = virtual_disk_handler;
	work->arg = cmnd;
	work->pool =session->work_pool;

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
	case STGT_KEVENT_START:
		dprintk("start %d\n", daemon_pid);
		break;
	case STGT_KEVENT_SCSI_CMND_RES:
		dprintk("start %llu\n", ev->u.msg_scsi_cmnd.cid);
		cmnd = find_cmnd_by_id(ev->u.msg_scsi_cmnd.cid);
		if (cmnd)
			uspace_cmnd_done(cmnd, (char *) ev + sizeof(*ev),
					 ev->u.msg_scsi_cmnd.size);
		else {
			eprintk("cannot found %llu\n", ev->u.msg_scsi_cmnd.cid);
			err = -EEXIST;
		}
		break;
	default:
		eprintk("unknown type %d\n", nlh->nlmsg_type);
		err = -EINVAL;
	}

	return err;
}

static int event_recv_skb(struct sk_buff *skb)
{
	int err;
	struct nlmsghdr	*nlh;
	u32 rlen;

	while (skb->len >= NLMSG_SPACE(0)) {
		nlh = (struct nlmsghdr *)skb->data;
		if (nlh->nlmsg_len < sizeof(*nlh) || skb->len < nlh->nlmsg_len)
			return 0;
		rlen = NLMSG_ALIGN(nlh->nlmsg_len);
		if (rlen > skb->len)
			rlen = skb->len;
		err = event_recv_msg(skb, nlh);
		if (err)
			netlink_ack(skb, nlh, -err);
		else if (nlh->nlmsg_flags & NLM_F_ACK)
			netlink_ack(skb, nlh, 0);
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
}

static int __init stgt_init(void)
{
	int i, err = -ENOMEM;

	spin_lock_init(&all_targets_lock);
	spin_lock_init(&atomic_sessions_lock);
	spin_lock_init(&cmnd_hash_lock);

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
