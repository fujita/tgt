struct target;
struct mgmt_req;

enum data_direction {
	DATA_NONE = 0,
	DATA_WRITE = 1,
	DATA_READ = 2,
	DATA_BIDIRECTIONAL = 3,
};

struct scsi_data_buffer {
	int resid;
};

struct scsi_cmd {
	struct target *c_target;
	/* linked it_nexus->cmd_hash_list */
	struct list_head c_hlist;
	struct list_head qlist;

	uint64_t dev_id;

	uint64_t uaddr;
	int mmapped;
	struct scsi_lu *dev;
	unsigned long state;

	struct scsi_data_buffer in_sdb;
	struct scsi_data_buffer out_sdb;

	uint32_t write_len;
	uint32_t read_len;
	enum data_direction data_dir;

	uint64_t cmd_itn_id;
	uint64_t offset;
	uint8_t *scb;
	int scb_len;
	uint8_t lun[8];
	int attribute;
	uint64_t tag;
	int async;
	int result;
	struct mgmt_req *mreq;

#define SCSI_SENSE_BUFFERSIZE	252
	unsigned char sense_buffer[SCSI_SENSE_BUFFERSIZE];
	int sense_len;

	/* workaround */
	struct list_head bs_list;
};

static inline void scsi_set_data_dir(struct scsi_cmd *scmd,
				     enum data_direction dir)
{
	scmd->data_dir = dir;
}

static inline enum data_direction scsi_get_data_dir(struct scsi_cmd *scmd)
{
	return scmd->data_dir;
}

static inline void scsi_set_result(struct scsi_cmd *scmd,
				   int result)
{
	scmd->result = result;
}

static inline int scsi_get_result(struct scsi_cmd *scmd)
{
	return scmd->result;
}

static inline void scsi_set_read_len(struct scsi_cmd *scmd, uint32_t read_len)
{
	scmd->read_len = read_len;
}

static inline uint32_t scsi_get_read_len(struct scsi_cmd *scmd)
{
	return scmd->read_len;
}

static inline void scsi_set_write_len(struct scsi_cmd *scmd, uint32_t write_len)
{
	scmd->write_len = write_len;
}

static inline uint32_t scsi_get_write_len(struct scsi_cmd *scmd)
{
	return scmd->write_len;
}

static inline void scsi_set_read_buffer(struct scsi_cmd *scmd, void *addr)
{
	scmd->uaddr = (unsigned long)addr;
}

static inline void *scsi_get_read_buffer(struct scsi_cmd *scmd)
{
	return (void *)(unsigned long)scmd->uaddr;
}

static inline void scsi_set_write_buffer(struct scsi_cmd *scmd, void *addr)
{
	scmd->uaddr = (unsigned long)addr;
}

static inline void *scsi_get_write_buffer(struct scsi_cmd *scmd)
{
	return (void *)(unsigned long)scmd->uaddr;
}

#define scsi_data_buffer_accessor(field, type)					\
	__scsi_data_buffer_accessor(in, field, type)				\
	__scsi_data_buffer_accessor(out, field, type)

#define __scsi_data_buffer_accessor(dir, field, type)				\
	scsi_cmnd_set_function(dir, field, type)				\
	scsi_cmnd_get_function(dir, field, type)

#define scsi_cmnd_set_function(dir, field, type)				\
static inline void scsi_set_##dir##_##field(struct scsi_cmd *scmd, type val)	\
{										\
	scmd->dir##_sdb.field = val;						\
}										\

#define scsi_cmnd_get_function(dir, field, type)				\
static inline type scsi_get_##dir##_##field(struct scsi_cmd *scmd)		\
{										\
	return scmd->dir##_sdb.field;						\
}										\

scsi_data_buffer_accessor(resid, int);

static inline void scsi_set_in_resid_by_actual(struct scsi_cmd *scmd,
					       uint32_t actual)
{
	scsi_set_in_resid(scmd, scsi_get_read_len(scmd) - actual);
}

static inline void scsi_set_out_resid_by_actual(struct scsi_cmd *scmd,
					       uint32_t actual)
{
	scsi_set_out_resid(scmd, scsi_get_write_len(scmd) - actual);
}
