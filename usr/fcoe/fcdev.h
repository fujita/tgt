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
 *
 */
#ifndef _FCDEV_H_
#define _FCDEV_H_

/*
 * This struct is created by an instance of a transport specific HBA driver.
 * The openfc driver and transport specific drivers use this structure.
 */
struct fcdev;
struct fc_scsi_pkt;
struct fc_frame;

/*
 * Ops vector for upper layer
 */
struct openfc_port_operations {
	/*
	 * interface to send FC frame
	 */
	int		(*send) (struct fcdev *hba, struct fc_frame *frame);

	/*
	 * interface to send scsi pkt to FCP State machine
	 */
	int		(*send_scsi) (struct fcdev *hba,
				      struct fc_scsi_pkt *fsp);

	/*
	 * i/f for abort, tgt reset, lun reset and hba reset
	 */

	int		(*abort_cmd) (struct fcdev *hba,
				      struct fc_scsi_pkt *fsp);
	int		(*target_reset) (struct fcdev *hba,
					 struct fc_scsi_pkt *fsp);
	int		(*bus_reset) (struct fcdev *hba);
	int		(*host_reset) (struct fcdev *hba,
					 struct fc_scsi_pkt *fsp);
	int		(*timeout_hdlr) (struct fcdev *hba,
					 struct fc_scsi_pkt *fsp);

	/*
	 * frame allocation routine
	 */
	struct fc_frame *(*frame_alloc)(size_t);
	ulong		alloc_flags;
	int		ext_fsp_size;
};

#define TRANS_LINK_UP	    0x01
#define TRANS_LINK_DOWN     0x02
/*
 * destination address mode
 * 0) Gateway based address
 * 1) FC OUI based address
 */
#define FCOE_GW_ADDR_MODE      0x00
#define FCOE_FCOUI_ADDR_MODE   0x01

#define FC_DFLT_LOGIN_TIMEOUT 10   /* 10sec */
#define FC_DFLT_LOGIN_RETRY   5
#define FC_INTR_DELAY_OFF     0
#define FC_INTR_DELAY_ON      1

/*
 * fcoe stats structure
 */
struct fcoe_dev_stats {
	uint64_t	SecondsSinceLastReset;
	uint64_t	TxFrames;
	uint64_t	TxWords;
	uint64_t	RxFrames;
	uint64_t	RxWords;
	uint64_t	ErrorFrames;
	uint64_t	DumpedFrames;
	uint64_t	LinkFailureCount;
	uint64_t	LossOfSignalCount;
	uint64_t	InvalidTxWordCount;
	uint64_t	InvalidCRCCount;
	uint64_t	InputRequests;
	uint64_t	OutputRequests;
	uint64_t	ControlRequests;
	uint64_t	InputMegabytes;
	uint64_t	OutputMegabytes;
};
/*
 * device specific information
 */
struct fc_drv_info {
	char 		model[64];
	char 		vendor[64];
	char 		sn[64];
	char 		model_desc[256];
	char 		hw_version[256];
	char 		fw_version[256];
	char 		opt_rom_version[256];
	char 		drv_version[128];
	char 		drv_name[128];
};

/*
 * Transport Capabilities
 */
#define TRANS_C_QUEUE	(1 << 0)  /*cmd queuing */
#define TRANS_C_CRC	(1 << 1)  /* FC CRC */
#define TRANS_C_DIF	(1 << 2)  /* t10 DIF */
#define TRANS_C_SG	(1 << 3)  /* Scatter gather */
#define TRANS_C_WSO	(1 << 4)  /* write seg offload */
#define TRANS_C_DDP	(1 << 5)  /* direct data placement for read */
/*
 * Transport Options
 */
#define TRANS_O_FCS_AUTO	(1 << 0) /* Bringup FCS at registratio time */

/*
 * transport  driver structure
 * one per instance of the driver
 */
struct fcdev {
	int fd;
	int mtu;

	unsigned long long fd_wwnn;	/* hba node name */
	unsigned long long fd_wwpn;	/* hba port name */
	int		fd_link_status;	/* link status */
	uint16_t	fd_speed;       /* link speed */
	uint16_t	fd_speed_support; /* supported link speeds */
	struct openfc_port_operations port_ops; /* transport op vector */
	/*
	 * driver specific stuff
	 */
	void		*drv_priv; 		/* private data */
	uint32_t 	capabilities;	 /* driver cap is defined here */
	uint32_t 	options;	 /* driver options is defined here */

	/*
	 * protocol related stuff
	 */
	char		ifname[IFNAMSIZ];
	uint32_t	framesize;
	fc_xid_t	min_xid;
	fc_xid_t	max_xid;

	/*
	 * Driver specific info used by HBA API
	 */
	struct fc_drv_info  drv_info;
	/*
	 * per cpu fc stat block
	 */
	struct fcoe_dev_stats *dev_stats[1];
};

/*
 * used by lower layer drive (fcoe)
 */
struct fcdev *	openfc_alloc_dev(struct openfc_port_operations *, int);
void		openfc_put_dev(struct fcdev *);
int		openfc_register(struct fcdev *);
void		openfc_rcv(struct fcdev *, struct fc_frame *);
void		openfc_unregister(struct fcdev *);
void		openfc_linkup(struct fcdev *);
void		openfc_linkdown(struct fcdev *);
void		openfc_pause(struct fcdev *);
void		openfc_unpause(struct fcdev *);

#endif /* _FCDEV_H_ */
