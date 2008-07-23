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
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <linux/if.h>

#include "list.h"
#include "log.h"
#include "util.h"
#include "tgtd.h"
#include "driver.h"
#include "target.h"

#include "fc_types.h"
#include "fc_frame.h"
#include "fc_encaps.h"
#include "fc_fcoe.h"
#include "fc_fcoe_old.h"
#include "fc_fs.h"
#include "fc_els.h"
#include "fcdev.h"
#include "fcoe_def.h"

extern int fcoe_cmd_done(uint64_t nid, int result, struct scsi_cmd *scmd);
extern int fcoe_tmf_done(struct mgmt_req *mreq);
extern int fcoe_target_create(struct target *t);
extern void fcoe_target_destroy(int tid);

static struct openfc_port_operations fcoe_port_ops = {
	.send = fcoe_xmit,
	.frame_alloc = fcoe_frame_alloc,
};

static void fcoe_nevent_handler(int fd, int events, void *data)
{
	if (events & EPOLLIN)
		fcoe_rcv((struct fcdev *)data);
}

static int fcoe_sock_open(struct fcdev *fdev)
{
	int fd, ret;
	struct sockaddr_ll sll;
	struct ifreq ifr;
	int ifindex;
	int mtu;

	fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (fd < 0) {
		eprintf("can't create a socket\n");
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, fdev->ifname, IFNAMSIZ);
	ret = ioctl(fd, SIOCGIFINDEX, &ifr);
	if (ret == -1) {
		return -1;
	}

	ifindex = ifr.ifr_ifindex;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, fdev->ifname, IFNAMSIZ);
	ioctl(fd, SIOCGIFFLAGS, &ifr);
	ifr.ifr_flags |= IFF_PROMISC;
	ioctl(fd, SIOCSIFFLAGS, &ifr);

	ret = ioctl(fd, SIOCGIFMTU, &ifr);
	mtu = ifr.ifr_mtu;

	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex	= ifindex;
/* 	sll.sll_protocol = htons(ETH_P_ALL); */
	sll.sll_protocol = htons(ETH_P_FCOE);

	ret = bind(fd, (struct sockaddr *)&sll, sizeof(sll));
	if (ret) {
		eprintf("can't bind\n");
		close(fd);
		return -1;
	}

	fdev->fd = fd;
	fdev->mtu = mtu;

	set_non_blocking(fd);

	return 0;
}

/*
 * Convert 48-bit IEEE MAC address to 64-bit FC WWN.
 */
fc_wwn_t fc_wwn_from_mac(u_int64_t mac, u_int scheme, u_int port)
{
	fc_wwn_t wwn;

	wwn = mac | ((fc_wwn_t) scheme << 60);
	switch (scheme) {
	case 1:
		break;
	case 2:
		wwn |= (fc_wwn_t) port << 48;
		break;
	default:
		break;
	}
	return wwn;
}

static int fcc_eth_get_mac(const char *ifname, int fd, net48_t *mac)
{
	struct ifreq ifr;
	int ret;

	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	ret = ioctl(fd, SIOCGIFHWADDR, &ifr);
	if (!ret && ifr.ifr_hwaddr.sa_family == ARPHRD_ETHER)
		memcpy(mac, ifr.ifr_hwaddr.sa_data, sizeof (*mac));

	return ret;
}

int fcoe_create_interface(char *ifname)
{
	struct fcdev *fdev;
	struct fcoe_softc *fc;
	int ret;
	uint64_t mac;

	fdev = openfc_alloc_dev(&fcoe_port_ops, sizeof(struct fcoe_softc));
	if (!fdev) {
		eprintf("fail to create openfc_dev\n");
		return -ENOMEM;
	}

	fc = (struct fcoe_softc *)fdev->drv_priv;
	fc->fcoe_hlen = sizeof(struct fcoe_hdr);

	/* todo */
	fdev->fd_link_status = TRANS_LINK_UP;

	if (!ifname) {
		eprintf("no interface specified.\n");
		return -ENODEV;
	}

	memcpy(fdev->ifname, ifname, IFNAMSIZ);

	ret = fcoe_sock_open(fdev);
	if (ret) {
		return ret;
	}

	fdev->framesize = fdev->mtu -
		(sizeof(struct fcoe_hdr) + sizeof(struct fcoe_crc_eof));

	fcc_eth_get_mac(ifname, fdev->fd, (net48_t *)fc->ctl_src_addr);

	mac = net48_get((net48_t *)fc->ctl_src_addr);

	net64_put((net64_t *)&fdev->fd_wwnn, fc_wwn_from_mac(mac, 1, 0));
	net64_put((net64_t *)&fdev->fd_wwpn, fc_wwn_from_mac(mac, 2, 0));

	snprintf(fdev->drv_info.model, 64, FCOE_DRIVER_NAME);
	snprintf(fdev->drv_info.vendor, 64, FCOE_DRIVER_VENDOR);
	snprintf(fdev->drv_info.model_desc, 64, FCOE_DRIVER_NAME);
/* 	snprintf(fdev->drv_info.drv_version, 64, BUILD_VERSION); */
	snprintf(fdev->drv_info.drv_name, 64, fdev->ifname);

	fdev->dev_stats[0] = zalloc(sizeof(struct fcoe_dev_stats));

	fc->fd = fdev;

	ret = openfc_register(fdev);
	if (ret) {
		return ret;
	}

	ret = tgt_event_add(fdev->fd, EPOLLIN, fcoe_nevent_handler, fdev);

	return 0;
}

static int fcoe_init(int index, char *args)
{
	eprintf("%s\n", args);
	return fcoe_create_interface(args);
}

static struct tgt_driver fcoe = {
	.name			= "fcoe",
	.use_kernel		= 0,
	.target_create		= fcoe_target_create,
	.target_destroy		= fcoe_target_destroy,
	.init			= fcoe_init,

	.cmd_end_notify		= fcoe_cmd_done,
	.mgmt_end_notify	= fcoe_tmf_done,
	.default_bst		= "rdwr",
};

__attribute__((constructor)) static void fcoe_driver_constructor(void)
{
	register_driver(&fcoe);
}
