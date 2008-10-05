/*
 * structure of a 'poor mans double linked list' on disk.
 */

/**
 * Block type definitations
 *
 * @BLK_NOOP:	No Operation.. Dummy value
 * @BLK_UNCOMPRESS_DATA:	If true, data block is uncompressed
 * @BLK_ENCRYPTED_DATA:		If true, data block is encrypted
 * @BLK_FILEMARK:		Represents a filemark
 * @BLK_SETMARK:		Represents a setmark
 * @BLK_BOT:			Represents a Beginning of Tape marker
 * @BLK_EOD:			Represents an End of Data marker
 *
 * Defines for types of SSC data blocks
 */
#define	BLK_NOOP		0x00000000
#define	BLK_COMPRESSED_DATA	0x00000001
#define	BLK_UNCOMPRESS_DATA	0x00000002
#define	BLK_ENCRYPTED_DATA	0x00000004
#define	BLK_BOT			0x00000010
#define	BLK_EOD			0x00000020
#define	BLK_FILEMARK		0x00000040
#define	BLK_SETMARK		0x00000080

#define TGT_TAPE_VERSION	2

struct blk_header {
	uint8_t a;
	uint32_t ondisk_sz;
	uint32_t blk_sz;
	uint32_t blk_type;
	uint64_t blk_num;
	uint64_t prev;
	uint64_t curr;
	uint64_t next;
	uint8_t z;
};

