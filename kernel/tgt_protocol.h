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

struct module;
struct tgt_cmnd;
struct tgt_session;

/*
 * The target driver will interact with tgt core through the protocol
 * handler. The protocol handler can then use the default tgt_core functions
 * or build wrappers around them.
 */
struct tgt_protocol {
	const char *name;
	struct module *module;

	kmem_cache_t *cmnd_cache;
	int uspace_pdu_size;

	/*
	 * create a command.
	 */
	struct tgt_cmnd *(* create_cmnd)(struct tgt_session *session,
					uint8_t *cmd, uint8_t *dev_id_buff,
					int buff_size);
	/*
	 * destroy a command. This will free the command and buffer
	 */
	void (* destroy_cmnd)(struct tgt_cmnd *cmd); 
	/*
	 * allocoate a comand buffer. If this is called from irq context
	 * a done callback can be set so the allocation is done in process
	 * context.
	 */
	void (* alloc_cmnd_buffer)(struct tgt_cmnd *cmnd,
				   void (*done)(struct tgt_cmnd *));
	/*
	 * queue a command to be executed in a workqueue. A done() callback
	 * must be passed in.
	 */
	int (* queue_cmnd)(struct tgt_cmnd *cmnd,
			   void (*done)(struct tgt_cmnd *));
	/*
	 * build userspace packet
	 */
	void (* build_uspace_pdu)(struct tgt_cmnd *cmnd, void *data);
};

extern void tgt_protocol_init(void);
extern int tgt_protocol_register(struct tgt_protocol *proto);
extern void tgt_protocol_unregister(struct tgt_protocol *proto);
extern struct tgt_protocol *tgt_protocol_get(const char *name);
extern void tgt_protocol_put(struct tgt_protocol *proto);

#endif
