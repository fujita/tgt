/*
 * SCSI target definitions
 */

struct Scsi_Host;
struct scsi_cmnd;
struct scsi_lun;

extern int scsi_tgt_alloc_queue(struct Scsi_Host *);
extern void scsi_tgt_queue_command(struct scsi_cmnd *, struct scsi_lun *, int);
