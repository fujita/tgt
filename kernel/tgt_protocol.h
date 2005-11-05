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
	unsigned priv_dev_data_size;

	/*
	 * Create a command and allocate a buffer of size data_len for
	 * for transfer. The buffer will be allocated with GFP_KERNEL
	 * and preprocesed by tgt/scsi_proto so the next time
	 * the target driver is notified about the cmd is when
	 * the transfer* is called.
	 */
	struct tgt_cmd *(* create_cmd)(struct tgt_session *session,
				       void *tgt_priv, uint8_t *cmd,
				       uint32_t data_len,
				       enum dma_data_direction data_dir,
				       uint8_t *dev_id_buff, int id_buff_size,
				       int flags);

	int (* execute_cmd) (struct tgt_cmd *cmd);
	void (* complete_cmd) (struct tgt_cmd *cmd);
	/*
	 * Build userspace packet
	 */
	void (* build_uspace_pdu)(struct tgt_cmd *cmd, void *data);

	/*
	 * Initialize protocol specific data per device
	 */
	void (* attach_device)(void *data);
	void (* detach_device)(void *data);
};

extern void tgt_protocol_init(void);
extern int tgt_protocol_register(struct tgt_protocol *proto);
extern void tgt_protocol_unregister(struct tgt_protocol *proto);
extern struct tgt_protocol *tgt_protocol_get(const char *name);
extern void tgt_protocol_put(struct tgt_protocol *proto);

#endif
