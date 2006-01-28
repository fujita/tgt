/*
 * Target Netlink Framework code
 *
 * (C) 2005 FUJITA Tomonori <tomof@acm.org>
 * (C) 2005 Mike Christie <michaelc@cs.wisc.edu>
 * This code is licenced under the GPL.
 */

#include <linux/netlink.h>
#include <linux/blkdev.h>
#include <net/tcp.h>
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

int scsi_tgt_uspace_send(struct scsi_cmnd *cmd, gfp_t gfp_mask)
{
	struct sk_buff *skb;
	struct nlmsghdr *nlh;
	struct tgt_event *ev;
	char *pdu;
	int len, err;
	pid_t pid;

	pid = scsi_tgt_get_pid(cmd->shost);
	len = NLMSG_SPACE(sizeof(*ev) + MAX_COMMAND_SIZE);
	/*
	 * TODO: add MAX_COMMAND_SIZE to ev and add mempool
	 */
	skb = alloc_skb(NLMSG_SPACE(len), gfp_mask);
	if (!skb)
		return -ENOMEM;

	dprintk("%p %d %Zd %d\n", cmd, len, sizeof(*ev), MAX_COMMAND_SIZE);
	nlh = __nlmsg_put(skb, pid, 0, TGT_KEVENT_CMD_REQ,
			  len - sizeof(*nlh), 0);
	ev = NLMSG_DATA(nlh);
	memset(ev, 0, sizeof(*ev));

	pdu = (char *) ev->data;
	ev->k.cmd_req.host_no = cmd->shost->host_no;
	ev->k.cmd_req.cid = cmd->request->tag;
	ev->k.cmd_req.data_len = cmd->request_bufflen;
	memcpy(ev->data, cmd->cmnd, MAX_COMMAND_SIZE);

	err = netlink_unicast(nls, skb, pid, 0);
	if (err < 0)
		printk(KERN_ERR "scsi_tgt_uspace_send: could not send skb "
		      "to pid %d err %d\n", pid, err);
	return err;
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

	memset(&ev, 0, sizeof(ev));
	ev.k.cmd_done.host_no = cmd->shost->host_no;
	ev.k.cmd_done.cid = (unsigned long)cmd;
	ev.k.cmd_done.result = cmd->result;

	return send_event_res(TGT_KEVENT_CMD_DONE, &ev, NULL, 0, gfp_mask,
			     scsi_tgt_get_pid(cmd->shost));
}

static int scsi_tgt_bind_host(struct tgt_event *ev)
{
	struct Scsi_Host *shost;
	struct task_struct *tsk;
	int err = 0;

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
	} else {
		eprintk("Could not find process %d\n",
			ev->u.target_bind.pid);
		err = EINVAL;
	}

	scsi_host_put(shost);
	return 0;
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
