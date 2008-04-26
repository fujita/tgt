#ifndef __TARGET_DAEMON_H
#define __TARGET_DAEMON_H

#include "log.h"
#include "scsi_cmnd.h"

#define SCSI_ID_LEN		24
#define SCSI_SN_LEN		8

#define VENDOR_ID_LEN		8
#define PRODUCT_ID_LEN		16
#define PRODUCT_REV_LEN		4

#define PCODE_SHIFT		7
#define PCODE_OFFSET(x) (x & ((1 << PCODE_SHIFT) - 1))

#define BLOCK_DESCRIPTOR_LEN	8
#define VERSION_DESCRIPTOR_LEN	8

#define VENDOR_ID	"IET"

#define _TAB1 "    "
#define _TAB2 _TAB1 _TAB1
#define _TAB3 _TAB1 _TAB1 _TAB1
#define _TAB4 _TAB2 _TAB2

enum tgt_system_state {
	TGT_SYSTEM_OFFLINE = 1,
	TGT_SYSTEM_READY,
};

enum scsi_target_state {
	SCSI_TARGET_OFFLINE = 1,
	SCSI_TARGET_RUNNING,
};

enum scsi_lu_state {
	SCSI_LU_OFFLINE = 1,
	SCSI_LU_RUNNING,
};

struct tgt_cmd_queue {
	int active_cmd;
	unsigned long state;
	struct list_head queue;
};

struct scsi_lu;

struct vpd {
	uint16_t size;
	void (*vpd_update)(struct scsi_lu *lu, void *data);
	uint8_t data[0];
};

struct lu_phy_attr {
	char scsi_id[SCSI_ID_LEN + 1];
	char scsi_sn[SCSI_SN_LEN + 1];

	char vendor_id[VENDOR_ID_LEN + 1];
	char product_id[PRODUCT_ID_LEN + 1];
	char product_rev[PRODUCT_REV_LEN + 1];

	uint16_t version_desc[VERSION_DESCRIPTOR_LEN];

 	char device_type;	/* Peripheral device type */
 	char qualifier;		/* Peripheral Qualifier */
	char removable;		/* Removable media */
	char online;		/* Logical Unit online */
	char sense_format;	/* Descrptor format sense data supported */

	/* VPD pages 0x80 -> 0xff masked with 0x80*/
	struct vpd *lu_vpd[1 << PCODE_SHIFT];
};

struct ua_sense {
	struct list_head ua_sense_siblings;
	unsigned char ua_sense_buffer[SCSI_SENSE_BUFFERSIZE];
	int ua_sense_len;
};

struct it_nexus_lu_info {
	struct scsi_lu *lu;
	struct list_head lu_info_siblings;
	struct list_head pending_ua_sense_list;
};

struct device_type_operations {
	int (*cmd_perform)(int host_no, struct scsi_cmd *cmd);
};

struct device_type_template {
	unsigned char type;

	int (*lu_init)(struct scsi_lu *lu);
	void (*lu_exit)(struct scsi_lu *lu);
	int (*lu_config)(struct scsi_lu *lu, char *args);

	struct device_type_operations ops[256];

	struct list_head device_type_siblings;
};

struct backingstore_template {
	const char *bs_name;
	int bs_datasize;
	int (*bs_open)(struct scsi_lu *dev, char *path, int *fd, uint64_t *size);
	void (*bs_close)(struct scsi_lu *dev);
	int (*bs_cmd_submit)(struct scsi_cmd *cmd);
	int (*bs_cmd_done)(struct scsi_cmd *cmd);

	struct list_head backingstore_siblings;
};

struct mode_pg {
	uint8_t pcode;		/* Page code */
	uint8_t subpcode;	/* Sub page code */
	int16_t pcode_size;	/* Size of page code data. */
	uint8_t mode_data[0];	/* Rest of mode page info */
};

struct scsi_lu {
	int fd;
	uint64_t addr; /* persistent mapped address */
	uint64_t size;
	uint64_t lun;
	char *path;

	/* the list of devices belonging to a target */
	struct list_head device_siblings;

	struct tgt_cmd_queue cmd_queue;

	enum scsi_lu_state lu_state;

	uint64_t reserve_id;

	/* we don't use a pointer because a lld could change this. */
	struct device_type_template dev_type_template;

	struct backingstore_template *bst;

	struct target *tgt;

	uint8_t	mode_block_descriptor[BLOCK_DESCRIPTOR_LEN];
	struct mode_pg *mode_pgs[0x3f];

	struct lu_phy_attr attrs;

	/* TODO: needs a structure for lots of device parameters */
	/* Currently only used by smc module */
	void *smc_p;
};

struct mgmt_req {
	uint64_t mid;
	int busy;
	int function;
	int result;

	/* for kernel llds */
	int host_no;
	uint64_t itn_id;
};

#ifdef USE_KERNEL
extern int kreq_init(void);
#else
static inline int kreq_init(void)	\
{					\
	return 0;			\
}
#endif

extern int kspace_send_tsk_mgmt_res(struct mgmt_req *mreq);
extern int kspace_send_cmd_res(uint64_t nid, int result, struct scsi_cmd *);

extern int ipc_init(void);
extern int tgt_device_create(int tid, int dev_type, uint64_t lun, char *args, int backing);
extern int tgt_device_destroy(int tid, uint64_t lun, int force);
extern int tgt_device_update(int tid, uint64_t dev_id, char *name);
extern int device_reserve(struct scsi_cmd *cmd);
extern int device_release(int tid, uint64_t itn_id, uint64_t lun, int force);
extern int device_reserved(struct scsi_cmd *cmd);

extern int tgt_target_create(int lld, int tid, char *args);
extern int tgt_target_destroy(int lld, int tid);
extern char *tgt_targetname(int tid);
extern int tgt_target_show_all(char *buf, int rest);
int system_set_state(char *str);
int system_show(int mode, char *buf, int rest);
int is_system_available(void);

extern int tgt_bind_host_to_target(int tid, int host_no);
extern int tgt_unbind_host_to_target(int tid, int host_no);
extern int tgt_bound_target_lookup(int host_no);

typedef void (event_handler_t)(int fd, int events, void *data);
typedef void (counter_event_handler_t)(int *counter, void *data);
extern int tgt_event_add(int fd, int events, event_handler_t handler, void *data);
extern int tgt_counter_event_add(int *counter, counter_event_handler_t handler,
				 void *data);
extern void tgt_event_del(int fd);
extern void tgt_counter_event_del(int *counter);
extern int tgt_event_modify(int fd, int events);
extern int target_cmd_queue(int tid, struct scsi_cmd *cmd);
extern void target_cmd_done(struct scsi_cmd *cmd);
struct scsi_cmd *target_cmd_lookup(int tid, uint64_t itn_id, uint64_t tag);
extern void target_mgmt_request(int tid, uint64_t itn_id, uint64_t req_id,
				int function, uint8_t *lun, uint64_t tag,
				int host_no);

extern void target_cmd_io_done(struct scsi_cmd *cmd, int result);
extern int ua_sense_del(struct scsi_cmd *cmd, int del);
extern void ua_sense_clear(struct it_nexus_lu_info *itn_lu, uint16_t asc);

extern uint64_t scsi_get_devid(int lid, uint8_t *pdu);
extern int scsi_cmd_perform(int host_no, struct scsi_cmd *cmd);
extern void sense_data_build(struct scsi_cmd *cmd, uint8_t key, uint16_t asc);
extern uint64_t scsi_rw_offset(uint8_t *scb);
extern int scsi_is_io_opcode(unsigned char op);
extern enum data_direction scsi_data_dir_opcode(unsigned char op);

extern enum scsi_target_state tgt_get_target_state(int tid);
extern int tgt_set_target_state(int tid, char *str);

extern int acl_add(int tid, char *address);
extern void acl_del(int tid, char *address);
extern char *acl_get(int tid, int idx);

extern int account_lookup(int tid, int type, char *user, int ulen, char *password, int plen);
extern int account_add(char *user, char *password);
extern void account_del(char *user);
extern int account_ctl(int tid, int type, char *user, int bind);
extern int account_show(char *buf, int rest);
extern int account_available(int tid, int dir);

extern int it_nexus_create(int tid, uint64_t itn_id, int host_no, char *info);
extern int it_nexus_destroy(int tid, uint64_t itn_id);

extern int device_type_register(struct device_type_template *);

extern struct lu_phy_attr *lu_attr_lookup(int tid, uint64_t lun);
extern int dtd_load_unload(int tid, uint64_t lun, int load, char *file);

extern int register_backingstore_template(struct backingstore_template *bst);
extern struct backingstore_template *get_backingstore_template(const char *name);

#endif
