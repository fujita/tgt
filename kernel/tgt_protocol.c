/*
 * Target protocol registration functions
 *
 * (C) 2005 FUJITA Tomonori <tomof@acm.org>
 * (C) 2005 Mike Christie <michaelc@cs.wisc.edu>
 * This code is licenced under the GPL.
 */
#include <linux/list.h>
#include <linux/module.h>
#include <tgt_protocol.h>

static spinlock_t protocol_lock;
static LIST_HEAD(protocol_list);

struct tgt_proto_internal {
	struct list_head list;
	struct tgt_protocol *proto;
};

struct tgt_protocol *tgt_protocol_get(const char *name)
{
	unsigned long flags;
	struct tgt_proto_internal *tp;

	spin_lock_irqsave(&protocol_lock, flags);
	list_for_each_entry(tp, &protocol_list, list)
		if (!strcmp(name, tp->proto->name)) {
			if (!try_module_get(tp->proto->module))
				tp = NULL;
			spin_unlock_irqrestore(&protocol_lock, flags);
			return tp ? tp->proto : NULL;
		}

	spin_unlock_irqrestore(&protocol_lock, flags);

	return NULL;
}

void tgt_protocol_put(struct tgt_protocol *proto)
{
	module_put(proto->module);
}

int tgt_protocol_register(struct tgt_protocol *proto)
{
	unsigned long flags;
	struct tgt_proto_internal *tp;

	tp = kmalloc(sizeof(*tp), GFP_KERNEL);
	if (!tp)
		return -ENOMEM;
	memset(tp, 0, sizeof(*tp));
	INIT_LIST_HEAD(&tp->list);
	tp->proto = proto;

	spin_lock_irqsave(&protocol_lock, flags);
	list_add_tail(&tp->list, &protocol_list);
	spin_unlock_irqrestore(&protocol_lock, flags);

	return 0;
}
EXPORT_SYMBOL_GPL(tgt_protocol_register);

void tgt_protocol_unregister(struct tgt_protocol *proto)
{
	unsigned long flags;
	struct tgt_proto_internal *tp;

	spin_lock_irqsave(&protocol_lock, flags);
	list_for_each_entry(tp, &protocol_list, list)
		if (tp->proto == proto) {
			list_del(&tp->list);
			kfree(tp);
			break;
		}

	spin_unlock_irqrestore(&protocol_lock, flags);
}
EXPORT_SYMBOL_GPL(tgt_protocol_unregister);

void __init tgt_protocol_init(void)
{
	spin_lock_init(&protocol_lock);
}
