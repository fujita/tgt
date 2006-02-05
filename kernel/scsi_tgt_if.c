/*
 * Target Netlink Framework code
 *
 * (C) 2005 FUJITA Tomonori <tomof@acm.org>
 * (C) 2005 Mike Christie <michaelc@cs.wisc.edu>
 * This code is licenced under the GPL.
 */

#include <linux/blkdev.h>
#include <linux/if_packet.h>
#include <linux/netlink.h>
#include <net/af_packet.h>
#include <net/tcp.h>
#include <scsi/scsi.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_tgt_if.h>

#include "scsi_tgt_priv.h"

/* default task when host is not setup in userspace yet */
static int tgtd_pid;
static struct sock *nls;

static int scsi_tgt_get_pid(struct Scsi_Host *shost)
{
	struct scsi_tgt_queuedata *queue = shost->uspace_req_q->queuedata;

	if (likely(queue->task))
		return queue->task->pid;
	else {
		printk(KERN_INFO "Sending cmd to tgtd. Host%d is unbound\n",
		       shost->host_no);
		return tgtd_pid;
	}
}

static struct sock *scsi_tgt_get_sock(struct Scsi_Host *shost)
{
	struct scsi_tgt_queuedata *queue = shost->uspace_req_q->queuedata;
	struct socket *sock = queue->sock;
	return sock ? sock->sk : NULL;
}

int scsi_tgt_uspace_send(struct scsi_cmnd *cmd)
{
	struct sock *sk;
	struct tpacket_hdr *h;
	struct tgt_event *ev;
	struct tgt_cmd *tcmd;

	sk = scsi_tgt_get_sock(cmd->shost);
	if (!sk) {
		printk(KERN_INFO "Host%d not connected\n",
		       cmd->shost->host_no);
		return -ENOTCONN;
	}

	h = packet_frame(sk);
	if (IS_ERR(h)) {
		eprintk("Queue is full\n");
		return PTR_ERR(h);
	}

	ev = (struct tgt_event *) ((char *) h + TPACKET_HDRLEN);

	ev->k.cmd_req.host_no = cmd->shost->host_no;
	ev->k.cmd_req.cid = cmd->request->tag;
	ev->k.cmd_req.data_len = cmd->request_bufflen;

	dprintk("%d %u %u\n", ev->k.cmd_req.host_no, ev->k.cmd_req.cid,
		ev->k.cmd_req.data_len);

	/* FIXME: we need scsi core to do that. */
	memcpy(cmd->cmnd, cmd->data_cmnd, MAX_COMMAND_SIZE);

	tcmd = (struct tgt_cmd *) ev->data;
	memcpy(tcmd->scb, cmd->cmnd, sizeof(tcmd->scb));
	memcpy(tcmd->lun, cmd->request->end_io_data, sizeof(struct scsi_lun));

	h->tp_status = TP_STATUS_USER;
	mb();
	{
		struct page *p_start, *p_end;
		char *h_end = (char *) h + TPACKET_HDRLEN +
			sizeof(struct tgt_event) + sizeof(struct tgt_cmd) - 1;

		p_start = virt_to_page(h);
		p_end = virt_to_page(h_end);
		while (p_start <= p_end) {
			flush_dcache_page(p_start);
			p_start++;
		}
	}

	sk->sk_data_ready(sk, 0);

	return 0;
}

static int send_event_res(uint16_t type, struct tgt_event *p,
			  void *data, int dlen, gfp_t flags, pid_t pid)
{
	struct tgt_event *ev;
	struct nlmsghdr *nlh;
	struct sk_buff *skb;
	uint32_t len;

	len = NLMSG_SPACE(sizeof(*ev) + dlen);
	skb = alloc_skb(len, flags);
	if (!skb)
		return -ENOMEM;

	nlh = __nlmsg_put(skb, pid, 0, type, len - sizeof(*nlh), 0);

	ev = NLMSG_DATA(nlh);
	memcpy(ev, p, sizeof(*ev));
	if (dlen)
		memcpy(ev->data, data, dlen);

	return netlink_unicast(nls, skb, pid, 0);
}

int scsi_tgt_uspace_send_status(struct scsi_cmnd *cmd, gfp_t gfp_mask)
{
	struct tgt_event ev;
	char dummy[MAX_COMMAND_SIZE + sizeof(struct scsi_lun)];

	memset(&ev, 0, sizeof(ev));
	ev.k.cmd_done.host_no = cmd->shost->host_no;
	ev.k.cmd_done.cid = cmd->request->tag;
	ev.k.cmd_done.result = cmd->result;

	return send_event_res(TGT_KEVENT_CMD_DONE, &ev, dummy, sizeof(dummy),
			      gfp_mask, scsi_tgt_get_pid(cmd->shost));
}

/* TODO: unbind to call fput. */
static int scsi_tgt_bind_host(struct tgt_event *ev)
{
	struct Scsi_Host *shost;
	struct task_struct *tsk;
	int err = 0;

	dprintk("%d %d %d\n", ev->u.target_bind.host_no,
		ev->u.target_bind.pid, ev->u.target_bind.psfd);

	shost = scsi_host_lookup(ev->u.target_bind.host_no);
	if (IS_ERR(shost)) {
		eprintk("Could not find host no %d\n",
			ev->u.target_bind.host_no);
			return -EINVAL;
	}

	tsk = find_task_by_pid(ev->u.target_bind.pid);
	if (tsk) {
		struct scsi_tgt_queuedata *queue;

		queue = shost->uspace_req_q->queuedata;
		queue->task = tsk;
		queue->sock = sockfd_lookup(ev->u.target_bind.psfd, &err);
	} else {
		eprintk("Could not find process %d\n",
			ev->u.target_bind.pid);
		err = EINVAL;
	}

	scsi_host_put(shost);
	return err;
}

static int event_recv_msg(struct sk_buff *skb, struct nlmsghdr *nlh)
{
	struct tgt_event *ev = NLMSG_DATA(nlh);
	int err = 0;

	dprintk("%d %d %d\n", nlh->nlmsg_type,
		nlh->nlmsg_pid, current->pid);

	switch (nlh->nlmsg_type) {
	case TGT_UEVENT_START:
		tgtd_pid = NETLINK_CREDS(skb)->pid;
		break;
	case TGT_UEVENT_TARGET_BIND:
		err = scsi_tgt_bind_host(ev);
		break;
	case TGT_UEVENT_CMD_RES:
		/* TODO: handle multiple cmds in one event */
		err = scsi_tgt_kspace_exec(ev->u.cmd_res.host_no,
					   ev->u.cmd_res.cid,
					   ev->u.cmd_res.result,
					   ev->u.cmd_res.len,
					   ev->u.cmd_res.offset,
					   ev->u.cmd_res.uaddr,
					   ev->u.cmd_res.rw,
					   ev->u.cmd_res.try_map);
		break;
	default:
		eprintk("unknown type %d\n", nlh->nlmsg_type);
		err = -EINVAL;
	}

	return err;
}

static int event_recv_skb(struct sk_buff *skb)
{
	int err;
	uint32_t rlen;
	struct nlmsghdr	*nlh;

	while (skb->len >= NLMSG_SPACE(0)) {
		nlh = (struct nlmsghdr *) skb->data;
		if (nlh->nlmsg_len < sizeof(*nlh) || skb->len < nlh->nlmsg_len)
			return 0;
		rlen = NLMSG_ALIGN(nlh->nlmsg_len);
		if (rlen > skb->len)
			rlen = skb->len;
		err = event_recv_msg(skb, nlh);

		dprintk("%d %d\n", nlh->nlmsg_type, err);
		/*
		 * TODO for passthru commands the lower level should
		 * probably handle the result or we should modify this
		 */
		if (nlh->nlmsg_type != TGT_UEVENT_CMD_RES) {
			struct tgt_event ev;

			memset(&ev, 0, sizeof(ev));
			ev.k.event_res.err = err;
			send_event_res(TGT_KEVENT_RESPONSE, &ev, NULL, 0,
				       GFP_KERNEL | __GFP_NOFAIL,
					nlh->nlmsg_pid);
		}
		skb_pull(skb, rlen);
	}
	return 0;
}

static void event_recv(struct sock *sk, int length)
{
	struct sk_buff *skb;

	while ((skb = skb_dequeue(&sk->sk_receive_queue))) {
		if (NETLINK_CREDS(skb)->uid) {
			skb_pull(skb, skb->len);
			kfree_skb(skb);
			continue;
		}

		if (event_recv_skb(skb) && skb->len)
			skb_queue_head(&sk->sk_receive_queue, skb);
		else
			kfree_skb(skb);
	}
}

void __exit scsi_tgt_nl_exit(void)
{
	sock_release(nls->sk_socket);
}

int __init scsi_tgt_nl_init(void)
{
	nls = netlink_kernel_create(NETLINK_TGT, 1, event_recv,
				    THIS_MODULE);
	if (!nls)
		return -ENOMEM;

	return 0;
}
