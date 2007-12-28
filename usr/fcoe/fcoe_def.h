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

#ifndef _FCOE_DEF_H_
#define _FCOE_DEF_H_

#include <netinet/if_ether.h>

#include "fc_fcoe.h"
#include "fc_exch.h"

#define FCOE_CLASS_NAME	    "fcoe"	/* class name for udev */
#define FCOE_CTL_DEV_NAME   "fcoe"	/* control device name for udev */
#define	FCOE_DRIVER_NAME    "fcoe"	/* driver name for ioctls */
#define	FCOE_DRIVER_VENDOR  "Open-FC.org" /* vendor name for ioctls */

#define FCOE_MIN_FRAME	36
#define FCOE_WORD_TO_BYTE  4

/*
 * this is the main  common structure across all instance of fcoe driver.
 * There is one to one mapping between hba struct and ethernet nic.
 * list of hbas contains pointer to the hba struct, these structures are
 * stored in this array using there corresponding if_index.
 */

struct fcoe_softc {
	struct list_head list;
	struct fcdev *fd;

        uint8_t    dest_addr[ETH_ALEN];
        uint8_t    ctl_src_addr[ETH_ALEN];
        uint8_t    data_src_addr[ETH_ALEN];
        /*
         * fcoe protocol address learning related stuff
         */
        uint16_t  flogi_oxid;
        uint8_t   flogi_progress;
        uint8_t   address_mode;
	uint8_t	  fcoe_hlen;		/* FCoE header length (implies ver) */
};

struct fcoe_rcv_info {
	struct fcdev 	*fd;
};

/*
 * HBA transport ops prototypes
 */
extern struct fcoe_info fcoei;

void fcoe_clean_pending_queue(struct fcdev *);
void fcoe_watchdog(ulong vp);
int fcoe_destroy_interface(struct fcdev *);
int fcoe_xmit(struct fcdev *, struct fc_frame *);
int fcoe_rcv(struct fcdev *);
struct fc_frame *fcoe_frame_alloc(size_t);
void fcoe_put_dev(struct fcdev *);
struct fcoe_softc *fcoe_find_fcdev(char *);
#endif /* _FCOE_DEF_H_ */
