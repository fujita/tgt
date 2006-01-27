/*
 * iSCSI digest handling.
 * (C) 2004 Xiranet Communications GmbH <arne.redlich@xiranet.com>
 * This code is licensed under the GPL.
 */

#include <linux/mm.h>
#include <asm/types.h>
#include <asm/scatterlist.h>
#include <linux/scatterlist.h>

#include <iscsi.h>
#include <digest.h>

void digest_alg_available(unsigned int *val)
{
	if (*val & DIGEST_CRC32C && !crypto_alg_available("crc32c", 0)) {
		printk("CRC32C digest algorithm not available in kernel\n");
		*val |= ~DIGEST_CRC32C;
	}
}

int digest_init(struct iscsi_conn *conn)
{
	int err = 0;

	if (!(conn->hdigest_type & DIGEST_ALL))
		conn->hdigest_type = DIGEST_NONE;

	if (!(conn->ddigest_type & DIGEST_ALL))
		conn->ddigest_type = DIGEST_NONE;

	if (conn->hdigest_type & DIGEST_CRC32C || conn->ddigest_type & DIGEST_CRC32C) {
		conn->rx_digest_tfm = crypto_alloc_tfm("crc32c", 0);
		if (!conn->rx_digest_tfm) {
			err = -ENOMEM;
			goto out;
		}

		conn->tx_digest_tfm = crypto_alloc_tfm("crc32c", 0);
		if (!conn->tx_digest_tfm) {
			err = -ENOMEM;
			goto out;
		}
	}

out:
	if (err)
		digest_cleanup(conn);

	return err;
}

void digest_cleanup(struct iscsi_conn *conn)
{
	if (conn->tx_digest_tfm)
		crypto_free_tfm(conn->tx_digest_tfm);
	if (conn->rx_digest_tfm)
		crypto_free_tfm(conn->rx_digest_tfm);
}

static void digest_header(struct crypto_tfm *tfm, struct iscsi_pdu *pdu,
			  uint8_t *crc)
{
	struct scatterlist sg[2];
	int i = 0;

	sg_init_one(&sg[i], (uint8_t *) &pdu->bhs, sizeof(struct iscsi_hdr));
	i++;
	if (pdu->ahssize) {
		sg_init_one(&sg[i], pdu->ahs, pdu->ahssize);
		i++;
	}

	crypto_digest_init(tfm);
	crypto_digest_update(tfm, sg, i);
	crypto_digest_final(tfm, crc);
}

int digest_rx_header(struct istgt_cmd *cmnd)
{
	uint32_t crc;

	digest_header(cmnd->conn->rx_digest_tfm, &cmnd->pdu, (uint8_t *) &crc);
	if (crc != cmnd->hdigest)
		return -EIO;

	return 0;
}

void digest_tx_header(struct istgt_cmd *cmnd)
{
	digest_header(cmnd->conn->tx_digest_tfm, &cmnd->pdu,
		      (uint8_t *) &cmnd->hdigest);
}

static void digest_data(struct crypto_tfm *tfm, struct istgt_cmd *cmnd,
			struct scatterlist *sgv, uint32_t offset, uint8_t *crc)
{
	struct scatterlist sg[ISCSI_CONN_IOV_MAX];
	uint32_t size, length;
	int i, idx, count;

	size = cmnd->pdu.datasize;
	size = (size + 3) & ~3;

	offset += sgv->offset;
	idx = offset >> PAGE_CACHE_SHIFT;
	offset &= ~PAGE_CACHE_MASK;
	count = get_pgcnt(size, offset);
	BUG_ON(count > ISCSI_CONN_IOV_MAX);
/* 	assert(idx + count <= tio->pg_cnt); */

	crypto_digest_init(tfm);

	for (i = 0; size; i++) {
		if (offset + size > PAGE_CACHE_SIZE)
			length = PAGE_CACHE_SIZE - offset;
		else
			length = size;

		sg[i].page = sgv[idx + i].page;
		sg[i].offset = offset;
		sg[i].length = length;
		size -= length;
		offset = 0;
	}

	crypto_digest_update(tfm, sg, count);
	crypto_digest_final(tfm, crc);
}

int digest_rx_data(struct istgt_cmd *cmnd)
{
	struct scatterlist *sg;
	uint32_t offset, crc;

	if (cmd_opcode(cmnd) == ISCSI_OP_SCSI_DATA_OUT) {
		struct istgt_cmd *scsi_cmnd = cmnd->req;
		struct iscsi_data *req = (struct iscsi_data *) &cmnd->pdu.bhs;

		sg = scsi_cmnd->scmd->request_buffer;
		offset = be32_to_cpu(req->offset);
	} else {
		sg = cmnd->scmd->request_buffer;
		offset = 0;
	}

	BUG_ON(!sg);
	digest_data(cmnd->conn->rx_digest_tfm, cmnd, sg, offset,
		    (uint8_t *) &crc);

	if (!cmnd->conn->read_overflow && (cmd_opcode(cmnd) != ISCSI_OP_PDU_REJECT)) {
		if (crc != cmnd->ddigest)
			return -EIO;
	}

	return 0;
}

void digest_tx_data(struct istgt_cmd *cmnd)
{
	struct iscsi_data *req = (struct iscsi_data *) &cmnd->pdu.bhs;

	BUG_ON(!cmnd->sg);
	digest_data(cmnd->conn->tx_digest_tfm, cmnd, cmnd->sg,
		    be32_to_cpu(req->offset), (uint8_t *) &cmnd->ddigest);
}
