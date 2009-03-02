/*
 * Copyright(c) 2007 Intel Corporation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 */
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>

#include "list.h"
#include "log.h"
#include "util.h"

#include "fc_types.h"
#include "fc_frame.h"
#include "fc_encaps.h"
#include "fc_fcoe.h"
#include "fc_fcoe_old.h"
#include "fcdev.h"
#include "fcoe_def.h"
#include "crc32_le.h"

/*
 * Snoop potential response to FLOGI or even incoming FLOGI.
 */
static void fcoe_recv_flogi(struct fcoe_softc *fc, struct fc_frame *fp,
			    uint64_t sa)
{
	struct fc_frame_header *fh;
	uint8_t op;

	fh = fc_frame_header_get(fp);
	if (fh->fh_type != FC_TYPE_ELS)
		return;
	op = fc_frame_payload_op(fp);
	if (op == ELS_LS_ACC && fh->fh_r_ctl == FC_RCTL_ELS_REP &&
	    fc->flogi_oxid == net16_get(&fh->fh_ox_id)) {
		/*
		 * FLOGI accepted.
		 * If the src mac addr is FC_OUI-based, then we mark the
		 * address_mode flag to use FC_OUI-based Ethernet DA.
		 * Otherwise we use the FCoE gateway addr
		 */
		if (sa == FC_FCOE_FLOGI_MAC)
			fc->address_mode = FCOE_FCOUI_ADDR_MODE;
		else {
			net48_put((net48_t *)&fc->dest_addr, sa);
			fc->address_mode = FCOE_GW_ADDR_MODE;
		}
		fc_fcoe_set_mac(fc->data_src_addr, (net24_t *) &fh->fh_d_id);

		fc->flogi_progress = 0;
	} else if (op == ELS_FLOGI && fh->fh_r_ctl == FC_RCTL_ELS_REQ && sa) {
		/*
		 * Save source MAC for point-to-point responses.
		 */
		net48_put((net48_t *)&fc->dest_addr, sa);
		fc->address_mode = FCOE_GW_ADDR_MODE;
	}
}

/*
 * Free a frame that was allocated by fcoe_alloc_frame().
 * The frame will be inside an sk_buff.
 */
static void fcoe_frame_free(struct fc_frame *fp)
{
	dprintf("%p\n", fp->fr_free_priv);
	if (fp->fr_destructor)
		fp->fr_destructor(fp->fr_arg);
	free(fp->fr_free_priv);
}

struct fc_frame *fcoe_frame_alloc(size_t len)
{
	struct fc_frame *fp;
	char *buf;

	len += sizeof(struct fc_frame_header);
	buf = malloc(len + sizeof(*fp) + FC_FRAME_HEADROOM + FC_FRAME_TAILROOM);
	if (!buf)
		return NULL;

	dprintf("%p\n", buf);

	fp = (struct fc_frame *)buf;
	fc_frame_init(fp);
	fp->fr_free = fcoe_frame_free;
	fp->fr_free_priv = buf;

	fp->fr_hdr = (struct fc_frame_header *)
		(buf + sizeof(*fp) + FC_FRAME_HEADROOM);
	fp->fr_len = len;
	fp->fr_destructor = NULL;

	return fp;
}

int fcoe_xmit(struct fcdev *fdev, struct fc_frame *fp)
{
	struct fcoe_softc *fc = (struct fcoe_softc *)fdev->drv_priv;
	struct fc_frame_header *fh;
	int flogi_in_progress = 0;
	uint8_t sof, eof;
	uint32_t crc, hlen, tlen;
	struct fcoe_crc_eof *cp;
	int wlen, ret, total;
	struct ethhdr *eh;
	struct fcoe_hdr *hp;

	dprintf("op %x\n", fc_frame_payload_op(fp));

	fh = fc_frame_header_get(fp);
	if (fh->fh_r_ctl == FC_RCTL_ELS_REQ) {
		if (fc_frame_payload_op(fp) == ELS_FLOGI) {
			fc->flogi_oxid = net16_get(&fh->fh_ox_id);
			fc->address_mode = FCOE_FCOUI_ADDR_MODE;
			fc->flogi_progress = 1;
			flogi_in_progress = 1;
		} else if (fc->flogi_progress && net24_get(&fh->fh_s_id) != 0) {
			/*
			 * Here we must've gotten an SID by accepting an FLOGI
			 * from a point-to-point connection.  Switch to using
			 * the source mac based on the SID.  The destination
			 * MAC in this case would have been set by receving the
			 * FLOGI.
			 */
			fc_fcoe_set_mac(fc->data_src_addr, &fh->fh_s_id);
			fc->flogi_progress = 0;
		}
	}

	sof = fp->fr_sof;
	eof = fp->fr_eof;

	crc = ~0;
	crc = crc32_sb8_64_bit(crc, (void *)fh, fp->fr_len);

	/*
	 * Get header and trailer lengths.
	 * This is temporary code until we get rid of the old protocol.
	 * Both versions have essentially the same trailer layout but T11
	 * has padding afterwards.
	 */
	hlen = fc->fcoe_hlen;
	tlen = sizeof(struct fcoe_crc_eof);

	cp = (struct fcoe_crc_eof *)((char *)fh + fp->fr_len);

	net8_put(&cp->fcoe_eof, eof);
	cp->fcoe_crc32 = ~crc;
	if (tlen == sizeof(*cp))
		memset(cp->fcoe_resvd, 0, sizeof(cp->fcoe_resvd));
	wlen = (fp->fr_len + sizeof(crc)) / FCOE_WORD_TO_BYTE;

	/*
	 *      Fill in the control structures
	 */
	eh = (struct ethhdr *)((char *)fh - (hlen + sizeof(*eh)));

	if (fc->address_mode == FCOE_FCOUI_ADDR_MODE)
		fc_fcoe_set_mac(eh->h_dest, (net24_t *) &fh->fh_d_id);
	else
		memcpy(eh->h_dest, fc->dest_addr, ETH_ALEN);

	if (flogi_in_progress)
		memcpy(eh->h_source, fc->ctl_src_addr, ETH_ALEN);
	else
		memcpy(eh->h_source, fc->data_src_addr, ETH_ALEN);

	eh->h_proto = htons(ETH_P_FCOE);

	hp = (struct fcoe_hdr *)(eh + 1);
	memset(hp, 0, sizeof(*hp));
	if (FC_FCOE_VER)
		FC_FCOE_ENCAPS_VER(hp, FC_FCOE_VER);
	hp->fcoe_sof = sof;

	total = fp->fr_len + tlen + sizeof(*eh) + hlen;
	ret = write(fdev->fd, eh, total);
	if (ret <= 0)
		eprintf("%d %d %d\n", fdev->fd, total, ret);
	fc_frame_free(fp);
	return 0;
}

int fcoe_rcv(struct fcdev *fdev)
{
	struct fc_frame_header *fh;
	char *buf;
	uint32_t fr_len;
	uint32_t hlen, tlen;
	struct fcoe_softc *fc;
	struct ethhdr *eh;
	uint64_t mac = 0;
	int ret;
	struct fcoe_dev_stats *stats;
	struct fcoe_crc_eof *cp;
	struct fc_frame *fp;
	struct fcoe_hdr *hp;

	fc = fdev->drv_priv;

	stats = fdev->dev_stats[0];
	fp = fcoe_frame_alloc(fdev->mtu);
	if (!fp)
		return 0;

	buf = (char *)fp->fr_hdr - (sizeof(*eh) + fc->fcoe_hlen);
	ret = read(fdev->fd, buf, fdev->mtu + sizeof(*eh));
	if (ret <= 0) {
		eprintf("%d\n", ret);
		goto out;
	}

	eh = (struct ethhdr *)buf;

	if (eh->h_proto != htons(ETH_P_FCOE)) {
		eprintf("wrong FC type frame, %x\n", eh->h_proto);
		goto out;
	}

	if (fc->flogi_progress)
		mac = net48_get((net48_t *)eh->h_source);

	hlen = fc->fcoe_hlen;
	if (hlen != sizeof(struct fcoe_hdr)) {
		eprintf("Wrong fcoe header size. Got %u, but should "
			"be %zu. Make sure you are using a initiator that "
			"is using the current header format\n",
			hlen, sizeof(struct fcoe_hdr));
		stats->ErrorFrames++;
		goto out;
	}

	hp = (struct fcoe_hdr *)(eh + 1);
	if (FC_FCOE_DECAPS_VER(hp) != FC_FCOE_VER) {
		eprintf("unknown FCoE version %x\n",
			FC_FCOE_DECAPS_VER(hp));
		stats->ErrorFrames++;
		free(buf);
		goto out;
	}
	fr_len = ret -(sizeof(*eh) +
		       sizeof(*hp) + sizeof(struct fcoe_crc_eof));
	tlen = sizeof(struct fcoe_crc_eof);

	if (fr_len + tlen > ret) {
		eprintf("short frame fr_len %x len %x\n",
			fr_len + tlen, ret);
		stats->ErrorFrames++;
		goto out;
	}

	dprintf("fr_len %d, hlen %d\n", fr_len, hlen);

	stats->RxFrames++;
	stats->RxWords += fr_len / FCOE_WORD_TO_BYTE;

	fc_frame_init_static(fp);
	fp->fr_len = fr_len;
	cp = (struct fcoe_crc_eof *)((char *)fp->fr_hdr + fr_len);
	fp->fr_eof = cp->fcoe_eof;
	fp->fr_sof = hp->fcoe_sof;

	/*
	 * Check the CRC here, unless it's solicited data for SCSI.
	 * In that case, the SCSI layer can check it during the copy,
	 * and it'll be more cache-efficient.
	 */
	fh = fc_frame_header_get(fp);
	if (fh->fh_r_ctl == FC_RCTL_DD_SOL_DATA &&
	    fh->fh_type == FC_TYPE_FCP) {
		fp->fr_flags |= FCPHF_CRC_UNCHECKED;
		openfc_rcv(fdev, fp);
	} else if (cp->fcoe_crc32 ==
		   ~crc32_sb8_64_bit(~0, (uint8_t *)fp->fr_hdr, fr_len)) {

		if (fc->flogi_progress)
			fcoe_recv_flogi(fc, fp, mac);
		openfc_rcv(fdev, fp);
	} else {
		eprintf("dropping frame with CRC error\n");

		stats->InvalidCRCCount++;
		stats->ErrorFrames++;
	}
out:
	fcoe_frame_free(fp);
	return 0;
}
