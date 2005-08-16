/*
 * Implementation for iSCSI iSNS support.
 * (C) 2004 Ming Zhang <mingz@ele.uri.edu>
 * This code is licenced under the GPL.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include "isns.h"
#include "iscsid.h"

static int cur_transaction_id = 0;
int sock_fd = -1;
int use_tcp = 1;
int isns_port = ISNS_PORT;
int use_isns = 0;

struct network_entity *iet_entity = NULL;
struct portal *iet_portal = NULL;

/*
 * wrapper to hide the TCP or UDP detail. currently we use TCP only
 */
int send_data(char *buf, int size)
{
	int i = 0;

	if (sock_fd == -1) {
		log_error("Wrong sock.\n");
		return -EINVAL;
	}
	do {
		buf += i;
		if ((i = send(sock_fd, buf, size, 0)) == -1) {
			log_error("Send data fail\n");
			return -EIO;
		}
		size -= i;
		if (size < 0) {
			log_error("What's wrong? \n");
			return -EIO;
		}
	} while (size);
	return 0;
}

/*
 * wrapper to hide the TCP or UDP detail currently we use TCP only
 */
int recv_data(char *buf, int size)
{
	int i = 0;

	if (sock_fd == -1) {
		log_error("Wrong sock.\n");
		return -EINVAL;
	}
	if ((i = recv(sock_fd, buf, size, 0)) == -1) {
		log_error("Recv data fail\n");
		return -EIO;
	}
	return i;
}

int init_isns_connection(int *fd, char *isnsip)
{
	struct sockaddr_in isns_addr;
	struct in_addr isns_in_addr;

	if (use_tcp) {
		if ((*fd = socket (AF_INET, SOCK_STREAM, 0)) < 0) {
			log_error("fail to create socket\n");
			return -EIO;
		}
		isns_addr.sin_family = AF_INET;
		isns_addr.sin_port = htons((short)isns_port);
		if (!inet_aton(isnsip, &isns_in_addr)) {
			log_error("invalid isns ip\n");
			return -EINVAL;
		}
		isns_addr.sin_addr.s_addr = isns_in_addr.s_addr;
		if (connect(*fd, (struct sockaddr *) &isns_addr, sizeof (isns_addr)) < 0) {
			log_error("fail to connect isns server\n");
			return -EIO;
		}
	}
	else {
		log_error("Unimplemented yet\n");
		return -EINVAL;
	}
	return 0;
}

void cleanup_connection(int fd)
{
	close(fd);
}

int send_pdu(struct isns_pdu *pdu, int pdu_size)
{
	/* FIXME: Lock protection */
	return send_data((char *)pdu->hdr, pdu_size);
}

int send_cmd(struct isns_cmd *cmd)
{
	return send_pdu(&cmd->pdu, cmd->cmd_size);
}

int recv_resp(struct isns_resp *resp, int function_id)
{
	int res;

	resp->resp_size = recv_data((char *)resp->pdu.hdr, MAX_ISNS_RESP_SIZE);
	log_debug(1, "recv %d\n", resp->resp_size);
	if (check_isns_hdr(resp->pdu.hdr, function_id)) {
		log_error("Invalid pdu hdr\n");
		return -EIO;
	}
	if ((res = check_isns_resp_status(&resp->pdu)) != ISNSP_RSP_SUCC) {
		log_error("fail request %d with status code %d\n", function_id, res);
		return -1;
	}
	return 0;
}

void init_tvllist(TLVLIST *p, int count)
{
	int i;

	if (count > MAX_TLV_CNT) {
		log_error("Invalid tlv count\n");
		return;
	}
	for (i = 0; i < count; i++) {
		p->tlv[i].attr_tag = INVALID_TAG;
		p->tlv[i].attr_len = NULL_SIZE;
		memset(p->tlv[i].attr_val, 0, MAX_TLV_VALUE_LEN);
	}
}

char *append_tlv(char *cur_buf, const struct tag_len_val *tlv)
{
	if (!cur_buf) {
		log_error("Invalid cur_buf in append_tlv\n");
		return cur_buf;
	}
	if (!tlv) {
		log_error("Invalid NULL tlv in append_tlv\n");
		return cur_buf;
	}
	if (tlv->attr_tag == INVALID_TAG)
		return cur_buf;

	if (tlv->attr_tag == ATTR_TAG_EID)
		log_debug(2, "attach EID: %ld,%s\n", tlv->attr_len, tlv->attr_val);

	*((u32 *)cur_buf) = htonl(tlv->attr_tag);
	*((u32 *)cur_buf + 1) = htonl(tlv->attr_len);
	if (tlv->attr_len)
		memcpy(cur_buf + 8, (char *)tlv->attr_val, tlv->attr_len);
	return (cur_buf + tlv->attr_len + 8);
}

int set_tlv_u32_data(struct tag_len_val *tvl, u32 data, u32 tag, long size)
{
	if (!tvl)
		return -EINVAL;

	/* keep tag and length in host order while data in network order */
	tvl->attr_tag = tag;
	tvl->attr_len = size;
	*(u32 *)tvl->attr_val = htonl(data);
	return 0;
}

int set_tlv_ip_data(struct tag_len_val *tvl, char *ip, u32 tag, long size)
{
	struct in_addr portal_ip;

	tvl->attr_tag = tag;
	tvl->attr_len = size;

	if (inet_aton(ip, &portal_ip)) {
		*((u32 *)tvl->attr_val) = 0x0;
		*((u32 *)tvl->attr_val + 1) = 0x0;
		*((u32 *)tvl->attr_val + 2) = htonl(0xFFFF);
		*((u32 *)tvl->attr_val + 3) = portal_ip.s_addr;
		return 0;
	}
	else {
		log_error("invalid ip\n");
		return -EINVAL;
	}
}

int set_tlv_string_data(struct tag_len_val *tvl, char *data, u16 tag, int maxlen)
{
	tvl->attr_tag = tag;
	tvl->attr_len = (data) ? Four_Bytes_Aligned(strlen(data)) : 0;
	if (tvl->attr_len > maxlen) {
		log_error("Wrong size of string data\n");
		return -EINVAL;
	}
	else {
		if (tvl->attr_len) {
			memset(tvl->attr_val, 0, tvl->attr_len);
			strcpy(tvl->attr_val, data);
		}
		return 0;
	}
}

#define init_network_entity(x) init_tvllist((TLVLIST *)x, 9)
#define set_tlv_entity_id(x, y) 		\
	set_tlv_string_data(x, y, ATTR_TAG_EID, ATTR_TAG_EID_SIZE)
#define set_tlv_entity_proto(x, y)	\
	set_tlv_u32_data(x, y, ATTR_TAG_ENTITY_PROTO, ATTR_TAG_ENTITY_PROTO_SIZE)
#define set_tlv_manage_ip(x, y)	\
	set_tlv_ip_data(x, y, ATTR_TAG_MANA_IP_ADDR, ATTR_TAG_MANA_IP_ADDR_SIZE)

#define init_storage_node(x) init_tvllist((TLVLIST *)x, 8)
#define set_tlv_iscsi_name(x, y) 		\
	set_tlv_string_data(x, y, ATTR_TAG_ISCSI_NAME, ATTR_TAG_ISCSI_NAME_SIZE)
#define set_tlv_iscsi_alias(x, y) 		\
	set_tlv_string_data(x, y, ATTR_TAG_ISCSI_ALIAS, ATTR_TAG_ISCSI_ALIAS_SIZE)
#define set_tlv_iscsi_auth_method(x, y) 		\
	set_tlv_string_data(x, y, ATTR_TAG_ISCSI_AUTH_METHOD, ATTR_TAG_ISCSI_AUTH_METHOD_SIZE)
#define set_tlv_iscsi_node_type(x, y)	\
	set_tlv_u32_data(x, 1UL << (31 - (y)), ATTR_TAG_NODE_TYPE, ATTR_TAG_NODE_TYPE_SIZE)

#define init_portal(x) init_tvllist((TLVLIST *)x, 11)
#define set_tlv_portal_ip(x, y)	\
	set_tlv_ip_data(x, y, ATTR_TAG_PORTAL_IP_ADDR, ATTR_TAG_PORTAL_IP_ADDR_SIZE)
#define set_tlv_portal_port(x, y)	\
	set_tlv_u32_data(x, y, ATTR_TAG_PORTAL_PORT, ATTR_TAG_PORTAL_PORT_SIZE)

#define init_portal_group(x) init_tvllist((TLVLIST *)x, 5)
#define set_tlv_pg_iscsi_name(x, y)	\
	set_tlv_string_data(x, y, ATTR_TAG_PG_ISCSI_NAME, ATTR_TAG_PG_ISCSI_NAME_SIZE)
#define set_tlv_pg_portal_ip(x, y)	\
	set_tlv_ip_data(x, y, ATTR_TAG_PG_PORTAL_IP_ADDR, ATTR_TAG_PG_PORTAL_IP_ADDR_SIZE)
#define set_tlv_pg_portal_port(x, y)	\
	set_tlv_u32_data(x, y, ATTR_TAG_PG_PORTAL_PORT, ATTR_TAG_PG_PORTAL_PORT_SIZE)
#define set_tlv_pg_tag(x, y)	\
	set_tlv_u32_data(x, y, ATTR_TAG_PG_TAG, ATTR_TAG_PG_TAG_SIZE)

#define init_discovery_domain(x) init_tvllist((TLVLIST *)x, 8)
#define init_discovery_domain_set(x) init_tvllist((TLVLIST *)x, 3)

int initialize_iet_entity(struct network_entity *entity)
{
	init_network_entity(entity);
	set_tlv_entity_proto(&entity->entity_proto, EP_ISCSI);
	return set_tlv_entity_id(&entity->eid, NULL);
}

int initialize_iet_portal(int port)
{
	int err;
	int fd;
	struct ifreq ifr;
	int i;
	struct portal *p;

	fd = socket(PF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		log_error("Can not create socket \n");
		return -EIO;
	}

	for (i = 0; i < 8; i++) {
		sprintf(ifr.ifr_name, "eth%d", i);
		ifr.ifr_addr.sa_family = AF_INET;
		if (ioctl(fd, SIOCGIFADDR, &ifr) == 0) {
			if (!(p = (struct portal *)malloc(sizeof(struct portal)))) {
				log_error("can not get memory for portal\n");
				err = -ENOMEM;
				break;
			}
			set_tlv_portal_ip(&p->portal_ip_addr, inet_ntoa(((struct sockaddr_in *)&(ifr.ifr_addr))->sin_addr));
			set_tlv_portal_port(&p->portal_port, port);
			p->next = iet_portal;
			iet_portal = p;
		}
		else {
			log_error("fail to get ip address for eth%d\n", i);
			break;
		}
	}
	close(fd);
	return 0;
}

int initialize_iet_isns(char *isnsip, int port)
{
	int err;
	struct portal *p;

	/*
	 * FIXME: currently only support one entity and one portal.
	 */
	if (!(iet_entity = (struct network_entity *)malloc(sizeof(struct network_entity)))) {
		log_error("can not get memory for iet_entity\n");
		return -ENOMEM;
	}
	if ((err = initialize_iet_entity(iet_entity)))
		goto fail;
	if ((err = initialize_iet_portal(port)))
		goto fail;
	if ((err = init_isns_connection(&sock_fd, isnsip)))
		goto fail;
	return 0;
fail:
	if (iet_entity)
		free(iet_entity);
	while (iet_portal) {
		p = iet_portal->next;
		free(iet_portal);
		iet_portal = p;
	};
	return err;
}

void cleanup_iet_isns(void)
{
	struct portal *p;

	cleanup_connection(sock_fd);
	if (iet_entity)
		free(iet_entity);
	while (iet_portal) {
		p = iet_portal->next;
		free(iet_portal);
		iet_portal = p;
	};
}

void get_next_transaction_id(u16 *transaction_id)
{
	/* FIXME: Lock protection */
	*transaction_id = cur_transaction_id++;
}

void get_cur_transaction_id(u16 *transaction_id)
{
	/* FIXME: Lock protection */
	*transaction_id = cur_transaction_id;
}

struct isns_cmd *allocate_isns_cmd(void)
{
	struct isns_cmd *cmd;

	if (!(cmd = (struct isns_cmd*)malloc(sizeof(struct isns_cmd))))
		return NULL;
	if (!(cmd->pdu.hdr = (struct isns_hdr *)malloc(MAX_ISNS_CMD_SIZE))) {
		free(cmd);
		return NULL;
	}
	cmd->pdu.pay_load = (((char *)cmd->pdu.hdr) + ISNS_HDR_LEN);
	cmd->pdu.authentication_block = NULL;
	cmd->cmd_size = ISNS_HDR_LEN;

	return cmd;
}

void free_isns_cmd(struct isns_cmd *cmd)
{
	if (cmd->pdu.authentication_block)
		free(cmd->pdu.authentication_block);
	if (cmd->pdu.hdr)
		free(cmd->pdu.hdr);
	free(cmd);
}

struct isns_resp *allocate_isns_resp(void)
{
	struct isns_resp *resp;

	if (!(resp = (struct isns_resp*)malloc(sizeof(struct isns_resp))))
		return NULL;
	if (!(resp->pdu.hdr = (struct isns_hdr *)malloc(MAX_ISNS_RESP_SIZE))) {
		free(resp);
		return NULL;
	}
	resp->pdu.pay_load = (((char *)resp->pdu.hdr) + ISNS_HDR_LEN);
	resp->pdu.authentication_block = NULL;

	return resp;
}

void free_isns_resp(struct isns_resp *resp)
{
	if (resp->pdu.authentication_block)
		free(resp->pdu.authentication_block);
	if (resp->pdu.hdr)
		free(resp->pdu.hdr);
	free(resp);
}

void init_isns_hdr(struct isns_hdr *hdr, int function_id, int replace)
{
	hdr->isnsp_version = htons((u16)ISNSP_VERSION);
	hdr->function_id = htons((u16)function_id);
	hdr->pdu_length = 0;
	hdr->flags = 0;
	/* always use one PDU for one command we send */
	set_bit_first_pdu(hdr->flags);
	set_bit_last_pdu(hdr->flags);
	set_bit_sender_client(hdr->flags);
	if (replace)
		set_bit_replace(hdr->flags);
	hdr->flags = htons((u16)hdr->flags);
	get_next_transaction_id(&hdr->transaction_id);
	hdr->transaction_id = htons((u16)hdr->transaction_id);
	hdr->sequence_id = 0;
}

int check_isns_hdr(struct isns_hdr *hdr, int function_id)
{
	if (ntohs(hdr->isnsp_version) != ISNSP_VERSION)
		return -EINVAL;
	if (ntohs(hdr->function_id) != function_id)
		return -EINVAL;
	/* TODO: more check here */
	return 0;
}

int check_isns_resp_status(struct isns_pdu *pdu)
{
	int status = ntohl(*(u32 *)pdu->pay_load);

	log_debug(1, "return status code %d\n", status);
	return status;
}

/* DD related functions */
int RegDD(void)
{
	return -EPERM;
}

int DeRegDD(void)
{
	return -EPERM;
}

/* DDS related functions */
int RegDDS(void)
{
	return -EPERM;
}

int DeRegDDS(void)
{
	return -EPERM;
}

/* Entity related functions */
int RegEntity(void)
{
	return -EPERM;
}

int DeRegEntity(struct network_entity *entity, struct tag_len_val *name)
{
	struct isns_cmd *cmd;
	struct isns_pdu *pdu;
	struct isns_resp *resp = NULL;
	char *buf;

	if (!entity) {
		log_error("Null entity to deregister.\n");
		return -EINVAL;
	}

	if (!(cmd = allocate_isns_cmd())) {
		log_error("allocate isns cmd fail\n");
		return -ENOMEM;
	}
	pdu = &cmd->pdu;
	init_isns_hdr(pdu->hdr, FUNC_DevDeReg, NO_REPLACE);
	buf = pdu->pay_load;
	buf = append_tlv(buf, name);
	buf = append_tlv(buf, &delimiter);
	buf = append_tlv(buf, &entity->eid);

	cmd->cmd_size = buf - (char *)pdu->hdr;
	pdu->hdr->pdu_length = htons((u16)(buf - (char *)pdu->pay_load));

	if (send_cmd(cmd)) {
		log_error("fail to send isns cmd\n");
		return -EIO;
	}
	if (!(resp = allocate_isns_resp())) {
		log_error("allocate isns resp fail\n");
		return -ENOMEM;
	}
	recv_resp(resp, FUNC_DevDeRegRsp);
	free_isns_resp(resp);

	return 0;
}

int QryEntity(void)
{
	return -EPERM;
}

int UpdateEntity(void)
{
	return -EPERM;
}

/* Node related functions */
struct storage_node *initialize_storage_node(char *name, char* alias)
{
	struct storage_node *p;

	if (!(p = (struct storage_node *)malloc(sizeof(struct storage_node)))) {
		log_error("fail to get memory for storage node\n");
		return NULL;
	}
	init_storage_node(p);

	set_tlv_iscsi_name(&p->iscsi_name, name);
	set_tlv_iscsi_node_type(&p->iscsi_node_type, NODE_TYPE_TARGET);
	set_tlv_iscsi_alias(&p->iscsi_alias, alias);
	return p;
}

void cleanup_storage_node(struct storage_node *node)
{
	free(node);
}

int RegNode(struct storage_node *node)
{
	struct isns_cmd *cmd;
	struct isns_pdu *pdu;
	struct isns_resp *resp = NULL;
	char *buf;
	struct portal *p;

	if (!node) {
		log_error("Null storage node to register.\n");
		return -EINVAL;
	}
	if (!(cmd = allocate_isns_cmd())) {
		log_error("allocate isns cmd fail\n");
		return -ENOMEM;
	}
	pdu = &cmd->pdu;
	init_isns_hdr(pdu->hdr, FUNC_DevAttrReg, NO_REPLACE);
	buf = pdu->pay_load;
	buf = append_tlv(buf, &node->iscsi_name);
	buf = append_tlv(buf, &delimiter);
	/* FIXME: assume one entity now */
	buf = append_tlv(buf, &iet_entity->eid);
	buf = append_tlv(buf, &iet_entity->entity_proto);

	for (p = iet_portal; p ; p = p->next) {
		buf = append_tlv(buf, &p->portal_ip_addr);
		buf = append_tlv(buf, &p->portal_port);
	}
	buf = append_tlv(buf, &node->iscsi_name);
	buf = append_tlv(buf, &node->iscsi_node_type);
	buf = append_tlv(buf, &node->iscsi_alias);
	buf = append_tlv(buf, &node->iscsi_auth_method);

	cmd->cmd_size = buf - (char *)pdu->hdr;
	pdu->hdr->pdu_length = htons((u16)(buf - (char *)pdu->pay_load));

	if (send_cmd(cmd)) {
		log_error("fail to send isns cmd\n");
		free_isns_cmd(cmd);
		return -EIO;
	}
	free_isns_cmd(cmd);

	if (!(resp = allocate_isns_resp())) {
		log_error("allocate isns resp fail\n");
		return -ENOMEM;
	}
	if (recv_resp(resp, FUNC_DevAttrRegRsp)) {
		free_isns_resp(resp);
		return -EIO;
	}
	if ((ntohl(*((u32 *)resp->pdu.pay_load + 1)) == ATTR_TAG_EID) &&
					!iet_entity->eid.attr_len) {
		// get assigned EID from iSNS server
		iet_entity->eid.attr_len = ntohl(*((u32 *)resp->pdu.pay_load + 2));
		memcpy(iet_entity->eid.attr_val, resp->pdu.pay_load + 8,
					ntohl(*((u32 *)resp->pdu.pay_load + 2)));
		log_debug(1, "new eid info, %ld, %s\n", iet_entity->eid.attr_len,
					iet_entity->eid.attr_val);
	}
	free_isns_resp(resp);
	return 0;
}

int DeRegNode(struct storage_node *node)
{
	struct isns_cmd *cmd;
	struct isns_pdu *pdu;
	struct isns_resp *resp = NULL;
	char *buf;

	if (!node) {
		log_error("Null storage node to deregister.\n");
		return -EINVAL;
	}

	if (!(cmd = allocate_isns_cmd())) {
		log_error("allocate isns cmd fail\n");
		return -ENOMEM;
	}
	pdu = &cmd->pdu;
	init_isns_hdr(pdu->hdr, FUNC_DevDeReg, NO_REPLACE);
	buf = pdu->pay_load;
	buf = append_tlv(buf, &node->iscsi_name);
	buf = append_tlv(buf, &delimiter);
	/* iscsi name can be as an operating attr for dereg */
	//buf = append_tlv(buf, &iet_entity->eid);
	buf = append_tlv(buf, &node->iscsi_name);

	cmd->cmd_size = buf - (char *)pdu->hdr;
	pdu->hdr->pdu_length = htons((u16)(buf - (char *)pdu->pay_load));

	if (send_cmd(cmd)) {
		log_error("fail to send isns cmd\n");
		return -EIO;
	}
	if (!(resp = allocate_isns_resp())) {
		log_error("allocate isns resp fail\n");
		return -ENOMEM;
	}
	recv_resp(resp, FUNC_DevDeRegRsp);
	free_isns_resp(resp);

	return 0;
}

int QryNode(void)
{
	return -EPERM;
}

int UpdateNode(void)
{
	return -EPERM;
}

/* Portal related functions */
int RegPortal(void)
{
	return -EPERM;
}

int DeRegPortal(struct portal *p, struct tag_len_val *name)
{
	struct isns_cmd *cmd;
	struct isns_pdu *pdu;
	struct isns_resp *resp = NULL;
	char *buf;

	if (!p) {
		log_error("Null portal to deregister.\n");
		return -EINVAL;
	}

	if (!(cmd = allocate_isns_cmd())) {
		log_error("allocate isns cmd fail\n");
		return -ENOMEM;
	}
	pdu = &cmd->pdu;
	init_isns_hdr(pdu->hdr, FUNC_DevDeReg, NO_REPLACE);
	buf = pdu->pay_load;
	buf = append_tlv(buf, name);
	buf = append_tlv(buf, &delimiter);
	buf = append_tlv(buf, &p->portal_ip_addr);
	buf = append_tlv(buf, &p->portal_port);

	cmd->cmd_size = buf - (char *)pdu->hdr;
	pdu->hdr->pdu_length = htons((u16)(buf - (char *)pdu->pay_load));

	if (send_cmd(cmd)) {
		log_error("fail to send isns cmd\n");
		return -EIO;
	}
	if (!(resp = allocate_isns_resp())) {
		log_error("allocate isns resp fail\n");
		return -ENOMEM;
	}
	recv_resp(resp, FUNC_DevDeRegRsp);
	free_isns_resp(resp);

	return 0;
}

int QryPortal(void)
{
	return -EPERM;
}

int UpdatePortal(void)
{
	return -EPERM;
}
