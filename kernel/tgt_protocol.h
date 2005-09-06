/*
 * Target protocol
 *
 * (C) 2005 FUJITA Tomonori <tomof@acm.org>
 * (C) 2005 Mike Christie <michaelc@cs.wisc.edu>
 * This code is licenced under the GPL.
 */
#ifndef __TGT_PROTOCOL_H
#define __TGT_PROTOCOL_H

struct module;
struct stgt_cmnd;

struct tgt_protocol {
	const char *name;
	struct module *module;

	int priv_cmd_data_size;
	/*
	 * perform command preparation, such as setting the rw field
	 * and dev_id
	 */
	void (* prep_cmnd)(struct stgt_cmnd *cmd, uint8_t *id_buff,
			   int buff_size);
	/*
	 * setup buffer fields like offset and len
	 */
	void (* init_cmnd_buffer)(struct stgt_cmnd *cmd);
	/*
	 * process completion of a command
	 */
	void (* cmnd_done)(struct stgt_cmnd *cmd, int err);
};

extern void tgt_protocol_init(void);
extern int tgt_protocol_register(struct tgt_protocol *proto);
extern void tgt_protocol_unregister(struct tgt_protocol *proto);
extern struct tgt_protocol *tgt_protocol_get(const char *name);
extern void tgt_protocol_put(struct tgt_protocol *proto);

#endif
