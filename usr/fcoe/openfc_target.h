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

#ifndef _OPENFCHBA_H_
#define _OPENFCHBA_H_

#include "fc_fcp.h"
#include "fcdev.h"

#define MAX_LUN         255
#define MAX_OUTSTANDING_COMMANDS 1024

struct os_tgt;
struct fc_scsi_pkt;
/*
 * openfc  hba state flages
 */
#define DCEHBA_INITIALIZATION       1
#define DCEHBA_FCS_INITIALIZATION   2
#define DCEHBA_DISCOVERY_DONE       3
#define DECHBA_RUNNING              4
#define DECHBA_GOING_DOWN           5

#define DCE_SRB_CACHEP_NAME 20
/*
 * openfc  hba state flages
 */
#define OPENFC_INITIALIZATION       1
#define OPENFC_FCS_INITIALIZATION   2
#define OPENFC_DISCOVERY_DONE       3
#define OPENFC_RUNNING              4
#define OPENFC_GOING_DOWN           5
/*
 * openfc hba status
 */
#define OPENFC_PAUSE                (1 << 1)
#define OPENFC_UNPAUSE              ~(OPENFC_PAUSE)
#define OPENFC_LINK_UP              (1 << 0)
#define OPENFC_LINK_DOWN             ~(OPENFC_LINK_UP)

/*
 * capabilites
 */

#define FCOE_FC_RAW_FRAME           1
#define FCOE_SCSI_IF                2
#define FCOE_ABORT_CMD              4
#define FCOE_TARGET_RESET           8
#define FCOE_IF_RESET               32
#define FCOE_SG_LIST                64

#define OPENFC_CRC_ENABLE           1
#define OPENFC_CRC_DISABLE          0

/*
 * openfc HBA software structure
 */
struct openfchba_softc {
	struct list_head            list;

	/*
	 * low level driver handle
	 */
	struct fcdev                *dev;       /* handle to lower level driver */
	struct fcs_state            *fcs_state; /* fcs state handle */
	struct fc_port              *fcs_port;  /* pointer to local port */
	uint16_t        state;
	uint16_t        status;
	short                       resrv;
	/*
	 * dchba_softc specific veriables
	 */
	u_int32_t                   capabilites;
	u_int32_t                   host_no;
	u_int32_t                   instance;

	/*
	 * below will be all FC specific
	 * parameters and trasport functions
	 */
	int                         login_timeout;
	int                         login_retries;
	ulong                       qdepth;
	struct list_head            rplist;

	struct fcdev    fd;
	struct openfct_tgt *tgt;
};

#define TGT_VALID 1
#define TGT_INVALID 0

struct os_tgt {
	struct list_head       list;
	struct fc_remote_port   *fcs_rport;
	struct fc_rport        *rport;
	u_int32_t               flags;
	struct openfchba_softc  *hba;
	fc_fid_t                fcid;
	u_int32_t               tid;

	/*
	 * Binding infodmation
	 */
	fc_wwn_t                node_name;
	fc_wwn_t                port_name;
};


struct fc_scsi_pkt * openfc_alloc_scsi_pkt(void *);
int openfc_free_scsi_pkt(struct fc_scsi_pkt *);
int openfc_destroy_scsi_slab(void);
int openfc_alloc_scsi_pkt_pool(void);
int openfc_create_scsi_slab(void);

int openfct_process_scsi_cmd(struct openfchba_softc *, struct fc_scsi_pkt *,
			     struct fcp_cmnd *);
int openfct_data_received(struct openfchba_softc *,
  struct fc_scsi_pkt *);

#endif /* _OPENFCHBA_H_ */
