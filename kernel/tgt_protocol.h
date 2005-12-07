/*
 * Target Framework Protocol definitions
 *
 * (C) 2005 FUJITA Tomonori <tomof@acm.org>
 * (C) 2005 Mike Christie <michaelc@cs.wisc.edu>
 * This code is licenced under the GPL.
 */
#ifndef __TGT_PROTOCOL_H
#define __TGT_PROTOCOL_H

#include <linux/slab.h>
#include <linux/dma-mapping.h>

struct module;
struct tgt_cmd;
struct tgt_session;

/*
 * The target driver will interact with tgt core through the protocol
 * handler. The protocol handler can then use the default tgt_core functions
 * or build wrappers around them.
 */
struct tgt_protocol {
	const char *name;
	struct module *module;

	kmem_cache_t *cmd_cache;
	unsigned uspace_pdu_size;
	/*
	 * Build userspace packet
	 */
	void (* uspace_pdu_build)(struct tgt_cmd *cmd, void *data);

	void (* uspace_cmd_complete)(struct tgt_cmd *cmd);
	void (* uspace_cmd_execute)(void *cmd);
};

extern void tgt_protocol_init(void);
extern int tgt_protocol_register(struct tgt_protocol *proto);
extern void tgt_protocol_unregister(struct tgt_protocol *proto);
extern struct tgt_protocol *tgt_protocol_get(const char *name);
extern void tgt_protocol_put(struct tgt_protocol *proto);

#endif
