#ifndef __SPC_H
#define __SPC_H

extern int spc_inquiry(int host_no, struct scsi_cmd *cmd);
extern int spc_report_luns(int host_no, struct scsi_cmd *cmd);
extern int spc_start_stop(int host_no, struct scsi_cmd *cmd);
extern int spc_test_unit(int host_no, struct scsi_cmd *cmd);
extern int spc_request_sense(int host_no, struct scsi_cmd *cmd);
extern int spc_illegal_op(int host_no, struct scsi_cmd *cmd);
extern int spc_lu_init(struct scsi_lu *lu);
extern int spc_lu_config(struct scsi_lu *lu, char * params);
extern void dump_cdb(struct scsi_cmd *cmd);

#endif
