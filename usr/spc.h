#ifndef __SPC_H
#define __SPC_H

extern int spc_inquiry(int host_no, struct scsi_cmd *cmd);
extern int spc_report_luns(int host_no, struct scsi_cmd *cmd);
extern int spc_start_stop(int host_no, struct scsi_cmd *cmd);
extern int spc_test_unit(int host_no, struct scsi_cmd *cmd);
extern int spc_request_sense(int host_no, struct scsi_cmd *cmd);
extern int spc_illegal_op(int host_no, struct scsi_cmd *cmd);
extern int spc_lu_init(struct scsi_lu *lu);

typedef int (match_fn_t)(struct scsi_lu *lu, char *params);
extern int lu_config(struct scsi_lu *lu, char *params, match_fn_t *);
extern int spc_lu_config(struct scsi_lu *lu, char *params);
extern void spc_lu_exit(struct scsi_lu *lu);
extern void dump_cdb(struct scsi_cmd *cmd);
extern int spc_mode_sense(int host_no, struct scsi_cmd *cmd);
extern int add_mode_page(struct scsi_lu *lu, char *params);
extern struct vpd *alloc_vpd(uint16_t size);
extern int spc_lu_online(struct scsi_lu *lu);
extern int spc_lu_offline(struct scsi_lu *lu);

#endif
