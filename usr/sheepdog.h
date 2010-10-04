#define SD_PROTO_VER 0x01

#define SD_DEFAULT_ADDR "localhost"
#define SD_DEFAULT_PORT "7000"

#define SD_OP_CREATE_AND_WRITE_OBJ  0x01
#define SD_OP_READ_OBJ       0x02
#define SD_OP_WRITE_OBJ      0x03

#define SD_OP_NEW_VDI        0x11
#define SD_OP_LOCK_VDI       0x12
#define SD_OP_RELEASE_VDI    0x13
#define SD_OP_GET_VDI_INFO   0x14
#define SD_OP_READ_VDIS      0x15

#define SD_FLAG_CMD_WRITE    0x01
#define SD_FLAG_CMD_COW      0x02

#define SD_RES_SUCCESS       0x00 /* Success */
#define SD_RES_UNKNOWN       0x01 /* Unknown error */
#define SD_RES_NO_OBJ        0x02 /* No object found */
#define SD_RES_EIO           0x03 /* I/O error */
#define SD_RES_VDI_EXIST     0x04 /* Vdi exists already */
#define SD_RES_INVALID_PARMS 0x05 /* Invalid parameters */
#define SD_RES_SYSTEM_ERROR  0x06 /* System error */
#define SD_RES_VDI_LOCKED    0x07 /* Vdi is locked */
#define SD_RES_NO_VDI        0x08 /* No vdi found */
#define SD_RES_NO_BASE_VDI   0x09 /* No base vdi found */
#define SD_RES_VDI_READ      0x0A /* Cannot read requested vdi */
#define SD_RES_VDI_WRITE     0x0B /* Cannot write requested vdi */
#define SD_RES_BASE_VDI_READ 0x0C /* Cannot read base vdi */
#define SD_RES_BASE_VDI_WRITE   0x0D /* Cannot write base vdi */
#define SD_RES_NO_TAG        0x0E /* Requested tag is not found */
#define SD_RES_STARTUP       0x0F /* Sheepdog is on starting up */
#define SD_RES_VDI_NOT_LOCKED   0x10 /* Vdi is not locked */
#define SD_RES_SHUTDOWN      0x11 /* Sheepdog is shutting down */
#define SD_RES_NO_MEM        0x12 /* Cannot allocate memory */
#define SD_RES_FULL_VDI      0x13 /* we already have the maximum vdis */
#define SD_RES_VER_MISMATCH  0x14 /* Protocol version mismatch */
#define SD_RES_NO_SPACE      0x15 /* Server has no room for new objects */
#define SD_RES_WAIT_FOR_FORMAT  0x16 /* Waiting for a format operation */
#define SD_RES_WAIT_FOR_JOIN    0x17 /* Waiting for other nodes joining */
#define SD_RES_JOIN_FAILED   0x18 /* Target node had failed to join sheepdog */

#define VDI_SPACE_SHIFT   32
#define VDI_BIT (UINT64_C(1) << 63)
#define VMSTATE_BIT (UINT64_C(1) << 62)
#define MAX_DATA_OBJS (UINT64_C(1) << 20)
#define MAX_CHILDREN 1024
#define SD_MAX_VDI_LEN 256
#define SD_MAX_VDI_TAG_LEN 256
#define SD_NR_VDIS   (1U << 24)
#define SD_DATA_OBJ_SIZE (UINT64_C(1) << 22)
#define SD_MAX_VDI_SIZE (SD_DATA_OBJ_SIZE * MAX_DATA_OBJS)
#define SECTOR_SIZE 512

#define SD_INODE_SIZE (sizeof(SheepdogInode))
#define CURRENT_VDI_ID 0

typedef struct SheepdogReq {
    uint8_t proto_ver;
    uint8_t opcode;
    uint16_t flags;
    uint32_t epoch;
    uint32_t id;
    uint32_t data_length;
    uint32_t opcode_specific[8];
} SheepdogReq;

typedef struct SheepdogRsp {
    uint8_t proto_ver;
    uint8_t opcode;
    uint16_t flags;
    uint32_t epoch;
    uint32_t id;
    uint32_t data_length;
    uint32_t result;
    uint32_t opcode_specific[7];
} SheepdogRsp;

typedef struct SheepdogObjReq {
    uint8_t proto_ver;
    uint8_t opcode;
    uint16_t flags;
    uint32_t epoch;
    uint32_t id;
    uint32_t data_length;
    uint64_t oid;
    uint64_t cow_oid;
    uint32_t copies;
    uint32_t rsvd;
    uint64_t offset;
} SheepdogObjReq;

typedef struct SheepdogObjRsp {
    uint8_t proto_ver;
    uint8_t opcode;
    uint16_t flags;
    uint32_t epoch;
    uint32_t id;
    uint32_t data_length;
    uint32_t result;
    uint32_t copies;
    uint32_t pad[6];
} SheepdogObjRsp;

typedef struct SheepdogVdiReq {
    uint8_t proto_ver;
    uint8_t opcode;
    uint16_t flags;
    uint32_t epoch;
    uint32_t id;
    uint32_t data_length;
    uint64_t vdi_size;
    uint32_t base_vdi_id;
    uint32_t copies;
    uint32_t snapid;
    uint32_t pad[3];
} SheepdogVdiReq;

typedef struct SheepdogVdiRsp {
    uint8_t proto_ver;
    uint8_t opcode;
    uint16_t flags;
    uint32_t epoch;
    uint32_t id;
    uint32_t data_length;
    uint32_t result;
    uint32_t rsvd;
    uint32_t vdi_id;
    uint32_t pad[5];
} SheepdogVdiRsp;

typedef struct SheepdogInode {
    char name[SD_MAX_VDI_LEN];
    char tag[SD_MAX_VDI_TAG_LEN];
    uint64_t ctime;
    uint64_t snap_ctime;
    uint64_t vm_clock_nsec;
    uint64_t vdi_size;
    uint64_t vm_state_size;
    uint16_t copy_policy;
    uint8_t nr_copies;
    uint8_t block_size_shift;
    uint32_t snap_id;
    uint32_t vdi_id;
    uint32_t parent_vdi_id;
    uint32_t child_vdi_id[MAX_CHILDREN];
    uint32_t data_vdi_id[MAX_DATA_OBJS];
} SheepdogInode;

struct sheepdog_access_info {
	int fd;
	struct SheepdogInode inode;
};

int sd_open(struct sheepdog_access_info *ai, char *filename, int flags);
int sd_io(struct sheepdog_access_info *ai, int write, char *buf,
	  int len, uint64_t offset);
