/*
 * Software iSCSI target protocol routines
 *
 * (C) 2005-2006 FUJITA Tomonori <tomof@acm.org>
 * (C) 2005-2006 Mike Christie <michaelc@cs.wisc.edu>
 *
 * This code is based on Ardis's iSCSI implementation.
 *   http://www.ardistech.com/iscsi/
 *   Copyright (C) 2002-2003 Ardis Technolgies <roman@ardistech.com>
 *   licensed under the terms of the GNU GPL v2.0,
 */
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <scsi/scsi.h>
#include <sys/epoll.h>

#include "iscsid.h"
#include "tgtd.h"
#include "util.h"

#define MAX_QUEUE_CMD	32

static struct iscsi_key login_keys[] = {
	{"InitiatorName",},
	{"InitiatorAlias",},
	{"SessionType",},
	{"TargetName",},
	{NULL, 0, 0, 0, NULL},
};

char *text_key_find(struct iscsi_connection *conn, char *searchKey)
{
	char *data, *key, *value;
	int keylen, datasize;

	keylen = strlen(searchKey);
	data = conn->req.data;
	datasize = conn->req.datasize;

	while (1) {
		for (key = data; datasize > 0 && *data != '='; data++, datasize--)
			;
		if (!datasize)
			return NULL;
		data++;
		datasize--;

		for (value = data; datasize > 0 && *data != 0; data++, datasize--)
			;
		if (!datasize)
			return NULL;
		data++;
		datasize--;

		if (keylen == value - key - 1
		     && !strncmp(key, searchKey, keylen))
			return value;
	}
}

static char *next_key(char **data, int *datasize, char **value)
{
	char *key, *p, *q;
	int size = *datasize;

	key = p = *data;
	for (; size > 0 && *p != '='; p++, size--)
		;
	if (!size)
		return NULL;
	*p++ = 0;
	size--;

	for (q = p; size > 0 && *p != 0; p++, size--)
		;
	if (!size)
		return NULL;
	p++;
	size--;

	*data = p;
	*value = q;
	*datasize = size;

	return key;
}

void text_key_add(struct iscsi_connection *conn, char *key, char *value)
{
	int keylen = strlen(key);
	int valuelen = strlen(value);
	int len = keylen + valuelen + 2;
	char *buffer;

	if (!conn->rsp.datasize)
		conn->rsp.data = conn->rsp_buffer;

	if (conn->tx_size + len > INCOMING_BUFSIZE) {
		log_warning("Dropping key (%s=%s)", key, value);
		return;
	}

	buffer = conn->rsp_buffer;
	buffer += conn->rsp.datasize;
	conn->rsp.datasize += len;

	strcpy(buffer, key);
	buffer += keylen;
	*buffer++ = '=';
	strcpy(buffer, value);
}

static void text_key_add_reject(struct iscsi_connection *conn, char *key)
{
	text_key_add(conn, key, "Reject");
}

static void text_scan_security(struct iscsi_connection *conn)
{
	struct iscsi_login_rsp *rsp = (struct iscsi_login_rsp *)&conn->rsp.bhs;
	char *key, *value, *data, *nextValue;
	int datasize;

	data = conn->req.data;
	datasize = conn->req.datasize;

	while ((key = next_key(&data, &datasize, &value))) {
		if (!(param_index_by_name(key, login_keys) < 0))
			;
		else if (!strcmp(key, "AuthMethod")) {
			do {
				nextValue = strchr(value, ',');
				if (nextValue)
					*nextValue++ = 0;

				if (!strcmp(value, "None")) {
					if (account_available(conn->tid, AUTH_DIR_INCOMING))
						continue;
					conn->auth_method = AUTH_NONE;
					text_key_add(conn, key, "None");
					break;
				} else if (!strcmp(value, "CHAP")) {
					if (!account_available(conn->tid, AUTH_DIR_INCOMING))
						continue;
					conn->auth_method = AUTH_CHAP;
					text_key_add(conn, key, "CHAP");
					break;
				}
			} while ((value = nextValue));

			if (conn->auth_method == AUTH_UNKNOWN)
				text_key_add_reject(conn, key);
		} else
			text_key_add(conn, key, "NotUnderstood");
	}
	if (conn->auth_method == AUTH_UNKNOWN) {
		rsp->status_class = ISCSI_STATUS_CLS_INITIATOR_ERR;
		rsp->status_detail = ISCSI_LOGIN_STATUS_AUTH_FAILED;
		conn->state = STATE_EXIT;
	}
}

static void login_security_done(struct iscsi_connection *conn)
{
	struct iscsi_login *req = (struct iscsi_login *)&conn->req.bhs;
	struct iscsi_login_rsp *rsp = (struct iscsi_login_rsp *) &conn->rsp.bhs;
	struct iscsi_session *session;

	if (!conn->tid)
		return;

	session = session_find_name(conn->tid, conn->initiator, req->isid);
	if (session) {
		if (!req->tsih) {
			/* do session reinstatement */
			/* We need to close all connections in this session */
/* 			session_conns_close(conn->tid, sid); */
/* 			session = NULL; */
		} else if (req->tsih != session->tsih) {
			/* fail the login */
			rsp->status_class = ISCSI_STATUS_CLS_INITIATOR_ERR;
			rsp->status_detail = ISCSI_LOGIN_STATUS_TGT_NOT_FOUND;
			conn->state = STATE_EXIT;
			return;
		} else if (conn_find(session, conn->cid)) {
			/* do connection reinstatement */
		}
		/* add a new connection to the session */
		conn_add_to_session(conn, session);
	} else {
		if (req->tsih) {
			/* fail the login */
			rsp->status_class = ISCSI_STATUS_CLS_INITIATOR_ERR;
			rsp->status_detail = ISCSI_LOGIN_STATUS_NO_SESSION;
			conn->state = STATE_EXIT;
			return;
		}
		/*
		 * We do nothing here and instantiate a new session
		 * later at login_finish().
		 */
	}
}

static void text_scan_login(struct iscsi_connection *conn)
{
	char *key, *value, *data;
	int datasize, idx;
	struct iscsi_login_rsp *rsp = (struct iscsi_login_rsp *)&conn->rsp.bhs;

	data = conn->req.data;
	datasize = conn->req.datasize;

	while ((key = next_key(&data, &datasize, &value))) {
		if (!(param_index_by_name(key, login_keys) < 0))
			;
		else if (!strcmp(key, "AuthMethod"))
			;
		else if (!((idx = param_index_by_name(key, session_keys)) < 0)) {
			int err;
			unsigned int val;
			char buf[32];

			if (idx == ISCSI_PARAM_MAX_RECV_DLENGTH)
				idx = ISCSI_PARAM_MAX_XMIT_DLENGTH;

			if (param_str_to_val(session_keys, idx, value, &val) < 0) {
				if (conn->session_param[idx].state
				    == KEY_STATE_START) {
					text_key_add_reject(conn, key);
					continue;
				} else {
					rsp->status_class =
						ISCSI_STATUS_CLS_INITIATOR_ERR;
					rsp->status_detail =
						ISCSI_LOGIN_STATUS_INIT_ERR;
					conn->state = STATE_EXIT;
					goto out;
				}
			}

			err = param_check_val(session_keys, idx, &val);
			err = param_set_val(session_keys, conn->session_param, idx, &val);

			switch (conn->session_param[idx].state) {
			case KEY_STATE_START:
				if (idx == ISCSI_PARAM_MAX_XMIT_DLENGTH)
					break;
				memset(buf, 0, sizeof(buf));
				param_val_to_str(session_keys, idx, val, buf);
				text_key_add(conn, key, buf);
				break;
			case KEY_STATE_REQUEST:
				if (val != conn->session_param[idx].val) {
					rsp->status_class =
						ISCSI_STATUS_CLS_INITIATOR_ERR;
					rsp->status_detail =
						ISCSI_LOGIN_STATUS_INIT_ERR;
					conn->state = STATE_EXIT;
					log_warning("%s %u %u\n", key,
					val, conn->session_param[idx].val);
					goto out;
				}
				break;
			case KEY_STATE_DONE:
				break;
			}
			conn->session_param[idx].state = KEY_STATE_DONE;
		} else
			text_key_add(conn, key, "NotUnderstood");
	}

out:
	return;
}

static int text_check_param(struct iscsi_connection *conn)
{
	struct param *p = conn->session_param;
	char buf[32];
	int i, cnt;

	for (i = 0, cnt = 0; session_keys[i].name; i++) {
		if (p[i].state == KEY_STATE_START && p[i].val != session_keys[i].def) {
			if (conn->state == STATE_LOGIN) {
				if (i == ISCSI_PARAM_MAX_XMIT_DLENGTH) {
					if (p[i].val > session_keys[i].def)
						p[i].val = session_keys[i].def;
					p[i].state = KEY_STATE_DONE;
					continue;
				}
				memset(buf, 0, sizeof(buf));
				param_val_to_str(session_keys, i, p[i].val,
						 buf);
				text_key_add(conn, session_keys[i].name, buf);
				p[i].state = KEY_STATE_REQUEST;
			}
			cnt++;
		}
	}

	return cnt;
}

static void login_start(struct iscsi_connection *conn)
{
	struct iscsi_login *req = (struct iscsi_login *)&conn->req.bhs;
	struct iscsi_login_rsp *rsp = (struct iscsi_login_rsp *)&conn->rsp.bhs;
	char *name, *alias, *session_type, *target_name;
	struct iscsi_target *target;

	conn->cid = be16_to_cpu(req->cid);
	memcpy(conn->isid, req->isid, sizeof(req->isid));
	conn->tsih = req->tsih;

	if (!sid64(conn->isid, conn->tsih)) {
		rsp->status_class = ISCSI_STATUS_CLS_INITIATOR_ERR;
		rsp->status_detail = ISCSI_LOGIN_STATUS_MISSING_FIELDS;
		conn->state = STATE_EXIT;
		return;
	}

	name = text_key_find(conn, "InitiatorName");
	if (!name) {
		rsp->status_class = ISCSI_STATUS_CLS_INITIATOR_ERR;
		rsp->status_detail = ISCSI_LOGIN_STATUS_MISSING_FIELDS;
		conn->state = STATE_EXIT;
		return;
	}
	conn->initiator = strdup(name);
	alias = text_key_find(conn, "InitiatorAlias");
	session_type = text_key_find(conn, "SessionType");
	target_name = text_key_find(conn, "TargetName");

	conn->auth_method = -1;
	conn->session_type = SESSION_NORMAL;

	if (session_type) {
		if (!strcmp(session_type, "Discovery"))
			conn->session_type = SESSION_DISCOVERY;
		else if (strcmp(session_type, "Normal")) {
			rsp->status_class = ISCSI_STATUS_CLS_INITIATOR_ERR;
			rsp->status_detail = ISCSI_LOGIN_STATUS_NO_SESSION_TYPE;
			conn->state = STATE_EXIT;
			return;
		}
	}

	if (conn->session_type == SESSION_NORMAL) {
		if (!target_name) {
			rsp->status_class = ISCSI_STATUS_CLS_INITIATOR_ERR;
			rsp->status_detail = ISCSI_LOGIN_STATUS_MISSING_FIELDS;
			conn->state = STATE_EXIT;
			return;
		}

		target = target_find_by_name(target_name);
		if (!target) {
			rsp->status_class = ISCSI_STATUS_CLS_INITIATOR_ERR;
			rsp->status_detail = ISCSI_LOGIN_STATUS_TGT_NOT_FOUND;
			conn->state = STATE_EXIT;
			return;
		}
		conn->tid = target->tid;

		if (tgt_get_target_state(target->tid) != SCSI_TARGET_RUNNING) {
			rsp->status_class = ISCSI_STATUS_CLS_TARGET_ERR;
			rsp->status_detail = ISCSI_LOGIN_STATUS_TARGET_ERROR;
			conn->state = STATE_EXIT;
			return;
		}

		if (ip_acl(conn->tid, conn->fd)) {
			rsp->status_class = ISCSI_STATUS_CLS_INITIATOR_ERR;
			rsp->status_detail = ISCSI_LOGIN_STATUS_TGT_NOT_FOUND;
			conn->state = STATE_EXIT;
			return;
		}

/* 		if (conn->target->max_sessions && */
/* 		    (++conn->target->session_cnt > conn->target->max_sessions)) { */
/* 			conn->target->session_cnt--; */
/* 			rsp->status_class = ISCSI_STATUS_INITIATOR_ERR; */
/* 			rsp->status_detail = ISCSI_STATUS_TOO_MANY_CONN; */
/* 			conn->state = STATE_EXIT; */
/* 			return; */
/* 		} */

		memcpy(conn->session_param, target->session_param,
		       sizeof(conn->session_param));
		conn->exp_cmd_sn = be32_to_cpu(req->cmdsn);
		dprintf("exp_cmd_sn: %d,%d\n", conn->exp_cmd_sn, req->cmdsn);
		conn->max_cmd_sn = conn->exp_cmd_sn;
	}
	text_key_add(conn, "TargetPortalGroupTag", "1");
}

static void login_finish(struct iscsi_connection *conn)
{
	switch (conn->session_type) {
	case SESSION_NORMAL:
		if (!conn->session)
			session_create(conn);
		memcpy(conn->isid, conn->session->isid, sizeof(conn->isid));
		conn->tsih = conn->session->tsih;
		break;
	case SESSION_DISCOVERY:
		/* set a dummy tsih value */
		conn->tsih = 1;
		break;
	}
}

static int cmnd_exec_auth(struct iscsi_connection *conn)
{
       int res;

        switch (conn->auth_method) {
        case AUTH_CHAP:
                res = cmnd_exec_auth_chap(conn);
                break;
        case AUTH_NONE:
                res = 0;
                break;
        default:
                eprintf("Unknown auth. method %d\n", conn->auth_method);
                res = -3;
        }

        return res;
}

static void cmnd_exec_login(struct iscsi_connection *conn)
{
	struct iscsi_login *req = (struct iscsi_login *)&conn->req.bhs;
	struct iscsi_login_rsp *rsp = (struct iscsi_login_rsp *)&conn->rsp.bhs;
	int stay = 0, nsg_disagree = 0;

	memset(rsp, 0, BHS_SIZE);
	if ((req->opcode & ISCSI_OPCODE_MASK) != ISCSI_OP_LOGIN ||
	    !(req->opcode & ISCSI_OP_IMMEDIATE)) {
		/* reject */
	}

	rsp->opcode = ISCSI_OP_LOGIN_RSP;
	rsp->max_version = ISCSI_DRAFT20_VERSION;
	rsp->active_version = ISCSI_DRAFT20_VERSION;
	rsp->itt = req->itt;

	if (/* req->max_version < ISCSI_VERSION || */
	    req->min_version > ISCSI_DRAFT20_VERSION) {
		rsp->status_class = ISCSI_STATUS_CLS_INITIATOR_ERR;
		rsp->status_detail = ISCSI_LOGIN_STATUS_NO_VERSION;
		conn->state = STATE_EXIT;
		return;
	}

	switch (ISCSI_LOGIN_CURRENT_STAGE(req->flags)) {
	case ISCSI_SECURITY_NEGOTIATION_STAGE:
		dprintf("Login request (security negotiation): %d", conn->state);
		rsp->flags = ISCSI_SECURITY_NEGOTIATION_STAGE << 2;

		switch (conn->state) {
		case STATE_FREE:
			conn->state = STATE_SECURITY;
			login_start(conn);
			if (rsp->status_class)
				return;
			/* fall through */
		case STATE_SECURITY:
			text_scan_security(conn);
			if (rsp->status_class)
				return;
			if (conn->auth_method != AUTH_NONE) {
				conn->state = STATE_SECURITY_AUTH;
				conn->auth_state = AUTH_STATE_START;
			}
			break;
		case STATE_SECURITY_AUTH:
			switch (cmnd_exec_auth(conn)) {
			case 0:
				break;
			default:
			case -1:
				goto init_err;
			case -2:
				goto auth_err;
			}
			break;
		default:
			goto init_err;
		}

		break;
	case ISCSI_OP_PARMS_NEGOTIATION_STAGE:
		dprintf("Login request (operational negotiation): %d\n",
			conn->state);
		rsp->flags = ISCSI_OP_PARMS_NEGOTIATION_STAGE << 2;

		switch (conn->state) {
		case STATE_FREE:
			conn->state = STATE_LOGIN;

			login_start(conn);
			if (account_available(conn->tid, AUTH_DIR_INCOMING))
				goto auth_err;
			if (rsp->status_class)
				return;
			text_scan_login(conn);
			if (rsp->status_class)
				return;
			stay = text_check_param(conn);
			break;
		case STATE_LOGIN:
			text_scan_login(conn);
			if (rsp->status_class)
				return;
			stay = text_check_param(conn);
			break;
		default:
			goto init_err;
		}
		break;
	default:
		goto init_err;
	}

	if (rsp->status_class)
		return;
	if (conn->state != STATE_SECURITY_AUTH &&
	    req->flags & ISCSI_FLAG_LOGIN_TRANSIT) {
		int nsg = ISCSI_LOGIN_NEXT_STAGE(req->flags);

		switch (nsg) {
		case ISCSI_OP_PARMS_NEGOTIATION_STAGE:
			switch (conn->state) {
			case STATE_SECURITY:
			case STATE_SECURITY_DONE:
				conn->state = STATE_SECURITY_LOGIN;
				login_security_done(conn);
				break;
			default:
				goto init_err;
			}
			break;
		case ISCSI_FULL_FEATURE_PHASE:
			switch (conn->state) {
			case STATE_SECURITY:
			case STATE_SECURITY_DONE:
				if ((nsg_disagree = text_check_param(conn))) {
					conn->state = STATE_LOGIN;
					nsg = ISCSI_OP_PARMS_NEGOTIATION_STAGE;
					break;
				}
				conn->state = STATE_SECURITY_FULL;
				login_security_done(conn);
				break;
			case STATE_LOGIN:
				if (stay)
					nsg = ISCSI_OP_PARMS_NEGOTIATION_STAGE;
				else
					conn->state = STATE_LOGIN_FULL;
				break;
			default:
				goto init_err;
			}
			if (!stay && !nsg_disagree)
				login_finish(conn);
			break;
		default:
			goto init_err;
		}
		rsp->flags |= nsg | (stay ? 0 : ISCSI_FLAG_LOGIN_TRANSIT);
	}

	memcpy(rsp->isid, conn->isid, sizeof(rsp->isid));
	rsp->tsih = conn->tsih;
	rsp->statsn = cpu_to_be32(conn->stat_sn++);
	rsp->exp_cmdsn = cpu_to_be32(conn->exp_cmd_sn);
	rsp->max_cmdsn = cpu_to_be32(conn->max_cmd_sn);
	return;
init_err:
	rsp->flags = 0;
	rsp->status_class = ISCSI_STATUS_CLS_INITIATOR_ERR;
	rsp->status_detail = ISCSI_LOGIN_STATUS_INIT_ERR;
	conn->state = STATE_EXIT;
	return;
auth_err:
	rsp->flags = 0;
	rsp->status_class = ISCSI_STATUS_CLS_INITIATOR_ERR;
	rsp->status_detail = ISCSI_LOGIN_STATUS_AUTH_FAILED;
	conn->state = STATE_EXIT;
	return;
}

static void text_scan_text(struct iscsi_connection *conn)
{
	char *key, *value, *data;
	int datasize;

	data = conn->req.data;
	datasize = conn->req.datasize;

	while ((key = next_key(&data, &datasize, &value))) {
		if (!strcmp(key, "SendTargets")) {
			struct sockaddr_storage ss;
			socklen_t slen, blen;
			char *p, buf[NI_MAXHOST + 128];

			if (value[0] == 0)
				continue;

			p = buf;
			blen = sizeof(buf);

			slen = sizeof(ss);
			getsockname(conn->fd, (struct sockaddr *) &ss, &slen);
			if (ss.ss_family == AF_INET6) {
				*p++ = '[';
				blen--;
			}

			slen = sizeof(ss);
			getnameinfo((struct sockaddr *) &ss, slen, p, blen,
				    NULL, 0, NI_NUMERICHOST);

			p = buf + strlen(buf);

			if (ss.ss_family == AF_INET6)
				 *p++ = ']';

			sprintf(p, ":%d,1", ISCSI_LISTEN_PORT);
			target_list_build(conn, buf,
					  strcmp(value, "All") ? value : NULL);
		} else
			text_key_add(conn, key, "NotUnderstood");
	}
}

static void cmnd_exec_text(struct iscsi_connection *conn)
{
	struct iscsi_text *req = (struct iscsi_text *)&conn->req.bhs;
	struct iscsi_text_rsp *rsp = (struct iscsi_text_rsp *)&conn->rsp.bhs;

	memset(rsp, 0, BHS_SIZE);

	if (be32_to_cpu(req->ttt) != 0xffffffff) {
		/* reject */;
	}
	rsp->opcode = ISCSI_OP_TEXT_RSP;
	rsp->itt = req->itt;
	/* rsp->ttt = rsp->ttt; */
	rsp->ttt = 0xffffffff;
	conn->exp_cmd_sn = be32_to_cpu(req->cmdsn);
	if (!(req->opcode & ISCSI_OP_IMMEDIATE))
		conn->exp_cmd_sn++;

	dprintf("Text request: %d\n", conn->state);
	text_scan_text(conn);

	if (req->flags & ISCSI_FLAG_CMD_FINAL)
		rsp->flags = ISCSI_FLAG_CMD_FINAL;

	rsp->statsn = cpu_to_be32(conn->stat_sn++);
	rsp->exp_cmdsn = cpu_to_be32(conn->exp_cmd_sn);
	rsp->max_cmdsn = cpu_to_be32(conn->max_cmd_sn);
}

static void cmnd_exec_logout(struct iscsi_connection *conn)
{
	struct iscsi_logout *req = (struct iscsi_logout *)&conn->req.bhs;
	struct iscsi_logout_rsp *rsp = (struct iscsi_logout_rsp *)&conn->rsp.bhs;

	memset(rsp, 0, BHS_SIZE);
	rsp->opcode = ISCSI_OP_LOGOUT_RSP;
	rsp->flags = ISCSI_FLAG_CMD_FINAL;
	rsp->itt = req->itt;
	conn->exp_cmd_sn = be32_to_cpu(req->cmdsn);
	if (!(req->opcode & ISCSI_OP_IMMEDIATE))
		conn->exp_cmd_sn++;

	rsp->statsn = cpu_to_be32(conn->stat_sn++);
	rsp->exp_cmdsn = cpu_to_be32(conn->exp_cmd_sn);
	rsp->max_cmdsn = cpu_to_be32(conn->max_cmd_sn);
}

static int cmnd_execute(struct iscsi_connection *conn)
{
	int res = 0;

	switch (conn->req.bhs.opcode & ISCSI_OPCODE_MASK) {
	case ISCSI_OP_LOGIN:
		cmnd_exec_login(conn);
		conn->rsp.bhs.hlength = conn->rsp.ahssize / 4;
		hton24(conn->rsp.bhs.dlength, conn->rsp.datasize);
		break;
	case ISCSI_OP_TEXT:
		cmnd_exec_text(conn);
		conn->rsp.bhs.hlength = conn->rsp.ahssize / 4;
		hton24(conn->rsp.bhs.dlength, conn->rsp.datasize);
		break;
	case ISCSI_OP_LOGOUT:
		cmnd_exec_logout(conn);
		conn->rsp.bhs.hlength = conn->rsp.ahssize / 4;
		hton24(conn->rsp.bhs.dlength, conn->rsp.datasize);
		break;
	default:
		/* reject */
		res = 1;
		break;
	}

	return res;
}

static void cmnd_finish(struct iscsi_connection *conn)
{
	switch (conn->state) {
	case STATE_EXIT:
		conn->state = STATE_CLOSE;
		break;
	case STATE_SECURITY_LOGIN:
		conn->state = STATE_LOGIN;
		break;
	case STATE_SECURITY_FULL:
		/* fall through */
	case STATE_LOGIN_FULL:
		if (conn->session_type == SESSION_NORMAL)
			conn->state = STATE_KERNEL;
		else
			conn->state = STATE_FULL;
		break;
	}
}

static int iscsi_cmd_rsp_build(struct iscsi_task *task)
{
	struct iscsi_connection *conn = task->conn;
	struct iscsi_cmd_rsp *rsp = (struct iscsi_cmd_rsp *) &conn->rsp.bhs;

	dprintf("%p %x\n", task, task->scmd.scb[0]);

	memset(rsp, 0, sizeof(*rsp));
	rsp->opcode = ISCSI_OP_SCSI_CMD_RSP;
	rsp->itt = task->tag;
	rsp->flags = ISCSI_FLAG_CMD_FINAL;
	rsp->response = ISCSI_STATUS_CMD_COMPLETED;
	rsp->cmd_status = task->result;
	rsp->statsn = cpu_to_be32(conn->stat_sn++);
	rsp->exp_cmdsn = cpu_to_be32(conn->session->exp_cmd_sn);
	rsp->max_cmdsn = cpu_to_be32(conn->session->exp_cmd_sn + MAX_QUEUE_CMD);

	return 0;
}

struct iscsi_sense_data {
	uint16_t length;
	uint8_t  data[0];
} __packed;

static int iscsi_sense_rsp_build(struct iscsi_task *task)
{
	struct iscsi_connection *conn = task->conn;
	struct iscsi_cmd_rsp *rsp = (struct iscsi_cmd_rsp *) &conn->rsp.bhs;
	struct iscsi_sense_data *sense;
	unsigned char sense_len;

	memset(rsp, 0, sizeof(*rsp));
	rsp->opcode = ISCSI_OP_SCSI_CMD_RSP;
	rsp->itt = task->tag;
	rsp->flags = ISCSI_FLAG_CMD_FINAL;
	rsp->response = ISCSI_STATUS_CMD_COMPLETED;
	rsp->cmd_status = SAM_STAT_CHECK_CONDITION;

	sense = (struct iscsi_sense_data *)task->scmd.sense_buffer;
	sense_len = task->scmd.sense_len;

	memmove(sense->data, sense, sense_len);
	sense->length = cpu_to_be16(sense_len);

	conn->rsp.datasize = sense_len + sizeof(*sense);
	hton24(rsp->dlength, sense_len + sizeof(*sense));
	conn->rsp.data = sense;

	return 0;
}

static int iscsi_data_rsp_build(struct iscsi_task *task)
{
	struct iscsi_connection *conn = task->conn;
	struct iscsi_data_rsp *rsp = (struct iscsi_data_rsp *) &conn->rsp.bhs;
	struct iscsi_cmd *req = (struct iscsi_cmd *) &task->req;
	int residual, datalen, exp_datalen = ntohl(req->data_length);
	int max_burst = conn->session_param[ISCSI_PARAM_MAX_XMIT_DLENGTH].val;

	memset(rsp, 0, sizeof(*rsp));
	rsp->opcode = ISCSI_OP_SCSI_DATA_IN;
	rsp->itt = task->tag;
	rsp->ttt = cpu_to_be32(ISCSI_RESERVED_TAG);
	rsp->cmd_status = ISCSI_STATUS_CMD_COMPLETED;

	rsp->offset = cpu_to_be32(task->offset);
	rsp->datasn = cpu_to_be32(task->data_sn++);
	rsp->cmd_status = task->result;

	datalen = min(exp_datalen, task->len);
	datalen -= task->offset;

	dprintf("%d %d %d %d %x\n", datalen, exp_datalen, task->len, max_burst, rsp->itt);

	if (datalen <= max_burst) {
		rsp->flags = ISCSI_FLAG_CMD_FINAL | ISCSI_FLAG_DATA_STATUS;
		if (task->len < exp_datalen) {
			rsp->flags |= ISCSI_FLAG_CMD_UNDERFLOW;
			residual = exp_datalen - task->len;
		} else if (task->len > exp_datalen) {
			rsp->flags |= ISCSI_FLAG_CMD_OVERFLOW;
			residual = task->len - exp_datalen;
		} else
			residual = 0;
		rsp->residual_count = cpu_to_be32(residual);
	} else
		datalen = max_burst;

	if (rsp->flags & ISCSI_FLAG_CMD_FINAL)
		rsp->statsn = cpu_to_be32(conn->stat_sn++);
	rsp->exp_cmdsn = cpu_to_be32(conn->session->exp_cmd_sn);
	rsp->max_cmdsn = cpu_to_be32(conn->session->exp_cmd_sn + MAX_QUEUE_CMD);

	conn->rsp.datasize = datalen;
	hton24(rsp->dlength, datalen);
	conn->rsp.data = (void *) (unsigned long) task->addr;
	conn->rsp.data += task->offset;

	task->offset += datalen;

	return 0;
}

static int iscsi_r2t_build(struct iscsi_task *task)
{
	struct iscsi_connection *conn = task->conn;
	struct iscsi_r2t_rsp *rsp = (struct iscsi_r2t_rsp *) &conn->rsp.bhs;
	int length, max_burst = conn->session_param[ISCSI_PARAM_MAX_XMIT_DLENGTH].val;

	memset(rsp, 0, sizeof(*rsp));

	rsp->opcode = ISCSI_OP_R2T;
	rsp->flags = ISCSI_FLAG_CMD_FINAL;
	memcpy(rsp->lun, task->req.lun, sizeof(rsp->lun));

	rsp->itt = task->req.itt;
	rsp->r2tsn = cpu_to_be32(task->exp_r2tsn++);
	rsp->data_offset = cpu_to_be32(task->offset);
	rsp->ttt = (unsigned long) task;
	length = min(task->r2t_count, max_burst);
	rsp->data_length = cpu_to_be32(length);

	return 0;
}

static inline struct iscsi_task *
iscsi_alloc_task(struct iscsi_connection *conn, int ext_len)
{
	struct iscsi_hdr *req = (struct iscsi_hdr *) &conn->req.bhs;
	struct iscsi_task *task;

	task = zalloc(sizeof(*task) + ext_len);
	if (!task)
		return NULL;

	memcpy(&task->req, req, sizeof(*req));
	task->conn = conn;
	INIT_LIST_HEAD(&task->c_hlist);
	INIT_LIST_HEAD(&task->c_list);

	conn_get(conn);
	return task;
}

void iscsi_free_task(struct iscsi_task *task)
{
	struct iscsi_connection *conn = task->conn;

	if (task->c_buffer)
		free(task->c_buffer);
	free(task);

	/* from alloc */
	conn_put(conn);
}

static inline struct iscsi_task *ITASK(struct scsi_cmd *scmd)
{
	return container_of(scmd, struct iscsi_task, scmd);
}

static void iscsi_free_cmd_task(struct iscsi_task *task)
{
	target_cmd_done(&task->scmd);

	list_del(&task->c_hlist);
	if (task->c_buffer) {
		if ((unsigned long) task->c_buffer != task->addr)
			free((void *) (unsigned long) task->addr);
	}
	iscsi_free_task(task);
}

int iscsi_scsi_cmd_done(uint64_t nid, int result, struct scsi_cmd *scmd)
{
	struct iscsi_task *task = ITASK(scmd);

	/*
	 * Since the connection is closed we just free the task.
	 * We could delay the closing of the conn in some cases and send
	 * the response with a little extra code or we can check if this
	 * task got reassinged to another connection.
	 */
	if (task->conn->state == STATE_CLOSE) {
		iscsi_free_cmd_task(task);
		return 0;
	}

	task->addr = scmd->uaddr;
	task->result = result;
	task->len = scmd->len;
	task->rw = scmd->rw;

	list_add_tail(&task->c_list, &task->conn->tx_clist);
	tgt_event_modify(task->conn->fd, EPOLLIN | EPOLLOUT);

	return 0;
}

static int cmd_attr(struct iscsi_task *task)
{
	int attr;
	struct iscsi_cmd *req = (struct iscsi_cmd *) &task->req;

	switch (req->flags & ISCSI_FLAG_CMD_ATTR_MASK) {
	case ISCSI_ATTR_UNTAGGED:
	case ISCSI_ATTR_SIMPLE:
		attr = SIMPLE_QUEUE_TAG;
		break;
	case ISCSI_ATTR_HEAD_OF_QUEUE:
		attr = HEAD_OF_QUEUE_TAG;
		break;
	case ISCSI_ATTR_ORDERED:
	default:
		attr = ORDERED_QUEUE_TAG;
	}
	return attr;
}

static int iscsi_target_cmd_queue(struct iscsi_task *task)
{
	struct scsi_cmd *scmd = &task->scmd;
	struct iscsi_connection *conn = task->conn;
	struct iscsi_cmd *req = (struct iscsi_cmd *) &task->req;
	unsigned long uaddr = (unsigned long) task->c_buffer;

	scmd->cmd_nexus_id = conn->session->iscsi_nexus_id;
	/* tmp hack */
	scmd->scb = req->cdb;
	scmd->scb_len = sizeof(req->cdb);

	memcpy(scmd->lun, task->req.lun, sizeof(scmd->lun));
	scmd->rw = req->flags & ISCSI_FLAG_CMD_WRITE;
	scmd->len = ntohl(req->data_length);
	scmd->attribute = cmd_attr(task);
	scmd->tag = req->itt;
	scmd->uaddr = uaddr;

	return target_cmd_queue(scmd);
}

static int iscsi_scsi_cmd_execute(struct iscsi_task *task)
{
	struct iscsi_connection *conn = task->conn;
	struct iscsi_cmd *req = (struct iscsi_cmd *) &task->req;
	int err = 0;

	if (req->flags & ISCSI_FLAG_CMD_WRITE) {
		if (task->r2t_count) {
			if (task->unsol_count)
				;
			else
				list_add_tail(&task->c_list, &task->conn->tx_clist);
		} else
			err = iscsi_target_cmd_queue(task);
	} else
		err = iscsi_target_cmd_queue(task);

	tgt_event_modify(conn->fd, EPOLLIN|EPOLLOUT);

	return err;
}

extern int iscsi_tm_done(uint64_t nid, uint64_t mid, int result)
{
	struct iscsi_task *task = (struct iscsi_task *) (unsigned long) mid;

	switch (result) {
	case 0:
		task->result = ISCSI_TMF_RSP_COMPLETE;
		break;
	case -EINVAL:
		task->result = ISCSI_TMF_RSP_NOT_SUPPORTED;
		break;
	case -EEXIST:
		/*
		 * the command completed or we could not find it so
		 * we retrun  no task here
		 */
		task->result = ISCSI_TMF_RSP_NO_TASK;
		break;
	default:
		task->result = ISCSI_TMF_RSP_REJECTED;
		break;
	}
	list_add_tail(&task->c_list, &task->conn->tx_clist);
	tgt_event_modify(task->conn->fd, EPOLLIN | EPOLLOUT);
	return 0;
}

static int iscsi_tm_execute(struct iscsi_task *task)
{
	struct iscsi_connection *conn = task->conn;
	struct iscsi_tm *req = (struct iscsi_tm *) &task->req;
	int fn, err = 0;

	switch (req->flags & ISCSI_FLAG_TM_FUNC_MASK) {
	case ISCSI_TM_FUNC_ABORT_TASK:
		fn = ABORT_TASK;
		break;
	case ISCSI_TM_FUNC_ABORT_TASK_SET:
		fn = ABORT_TASK_SET;
		break;
	case ISCSI_TM_FUNC_CLEAR_ACA:
		fn = CLEAR_TASK_SET;
		break;
	case ISCSI_TM_FUNC_CLEAR_TASK_SET:
		fn = CLEAR_ACA;
		break;
	case ISCSI_TM_FUNC_LOGICAL_UNIT_RESET:
		fn = LOGICAL_UNIT_RESET;
		break;
	case ISCSI_TM_FUNC_TARGET_WARM_RESET:
	case ISCSI_TM_FUNC_TARGET_COLD_RESET:
	case ISCSI_TM_FUNC_TASK_REASSIGN:
		err = ISCSI_TMF_RSP_NOT_SUPPORTED;
		break;
	default:
		err = ISCSI_TMF_RSP_REJECTED;

		eprintf("unknown task management function %d\n",
			req->flags & ISCSI_FLAG_TM_FUNC_MASK);
	}

	if (err)
		task->result = err;
	else
		target_mgmt_request(conn->session->iscsi_nexus_id,
				    (unsigned long) task, fn, req->lun, req->itt);
	return err;
}

static int iscsi_task_execute(struct iscsi_task *task)
{
	struct iscsi_hdr *hdr = (struct iscsi_hdr *) &task->req;
	uint8_t op = hdr->opcode & ISCSI_OPCODE_MASK;
	int err;

	switch (op) {
	case ISCSI_OP_NOOP_OUT:
	case ISCSI_OP_LOGOUT:
		list_add_tail(&task->c_list, &task->conn->tx_clist);
		tgt_event_modify(task->conn->fd, EPOLLIN | EPOLLOUT);
		break;
	case ISCSI_OP_SCSI_CMD:
		err = iscsi_scsi_cmd_execute(task);
		break;
	case ISCSI_OP_SCSI_TMFUNC:
		err = iscsi_tm_execute(task);
		if (err) {
			list_add_tail(&task->c_list, &task->conn->tx_clist);
			tgt_event_modify(task->conn->fd, EPOLLIN | EPOLLOUT);
		}
		break;
	case ISCSI_OP_TEXT:
	case ISCSI_OP_SNACK:
		break;
	default:
		break;
	}

	return 0;
}

static int iscsi_data_out_rx_done(struct iscsi_task *task)
{
	struct iscsi_hdr *hdr = &task->conn->req.bhs;
	int err = 0;

	if (hdr->ttt == cpu_to_be32(ISCSI_RESERVED_TAG)) {
		if (hdr->flags & ISCSI_FLAG_CMD_FINAL) {
			task->unsol_count = 0;
			if (!task_pending(task))
				err = iscsi_scsi_cmd_execute(task);
		}
	} else {
		if (!(hdr->flags & ISCSI_FLAG_CMD_FINAL))
			return err;

		err = iscsi_scsi_cmd_execute(task);
	}

	return err;
}

static int iscsi_data_out_rx_start(struct iscsi_connection *conn)
{
	struct iscsi_task *task;
	struct iscsi_data *req = (struct iscsi_data *) &conn->req.bhs;

	list_for_each_entry(task, &conn->session->cmd_list, c_hlist) {
		if (task->tag == req->itt)
			goto found;
	}
	return -EINVAL;
found:
	dprintf("found a task %" PRIx64 " %u %u %u %u %u\n", task->tag,
		ntohl(((struct iscsi_cmd *) (&task->req))->data_length),
		task->offset,
		task->r2t_count,
		ntoh24(req->dlength), be32_to_cpu(req->offset));

	conn->rx_buffer = (void *) (unsigned long) task->c_buffer;
	conn->rx_buffer += be32_to_cpu(req->offset);
	conn->rx_size = ntoh24(req->dlength);

	task->offset += ntoh24(req->dlength);
	task->r2t_count -= ntoh24(req->dlength);

	conn->rx_task = task;

	return 0;
}

static int iscsi_task_queue(struct iscsi_task *task)
{
	struct iscsi_session *session = task->conn->session;
	struct iscsi_hdr *req = (struct iscsi_hdr *) &task->req;
	uint32_t cmd_sn;
	struct iscsi_task *ent;
	int err;

	dprintf("%x %x %x\n", be32_to_cpu(req->statsn), session->exp_cmd_sn,
		req->opcode);

	if (req->opcode & ISCSI_OP_IMMEDIATE)
		return iscsi_task_execute(task);

	cmd_sn = be32_to_cpu(req->statsn);
	if (cmd_sn == session->exp_cmd_sn) {
	retry:
		session->exp_cmd_sn = ++cmd_sn;

		/* Should we close the connection... */
		err = iscsi_task_execute(task);

		if (list_empty(&session->pending_cmd_list))
			return 0;
		task = list_entry(session->pending_cmd_list.next,
				   struct iscsi_task, c_list);
		if (be32_to_cpu(task->req.statsn) != cmd_sn)
			return 0;

		list_del(&task->c_list);
		clear_task_pending(task);
		goto retry;
	} else {
		if (before(cmd_sn, session->exp_cmd_sn)) {
			eprintf("unexpected cmd_sn (%u,%u)\n",
				cmd_sn, session->exp_cmd_sn);
			return -EINVAL;
		}

		/* TODO: check max cmd_sn */

		list_for_each_entry(ent, &session->pending_cmd_list, c_list) {
			if (before(cmd_sn, be32_to_cpu(ent->req.statsn)))
				break;
		}

		list_add_tail(&task->c_list, &ent->c_list);
		set_task_pending(task);
	}
	return 0;
}

static int iscsi_scsi_cmd_rx_start(struct iscsi_connection *conn)
{
	struct iscsi_cmd *req = (struct iscsi_cmd *) &conn->req.bhs;
	struct iscsi_task *task;
	int len;

	task = iscsi_alloc_task(conn, 0);
	if (task)
		conn->rx_task = task;
	else
		return -ENOMEM;
	task->tag = req->itt;

	dprintf("%u %x %d %d %x\n", conn->session->tsih,
		req->cdb[0], ntohl(req->data_length),
		req->flags & ISCSI_FLAG_CMD_ATTR_MASK, req->itt);

	len = ntohl(req->data_length);
	if (len) {
		task->c_buffer = valloc(len);
		if (!task->c_buffer) {
			iscsi_free_task(task);
			return -ENOMEM;
		}
		dprintf("%p\n", task->c_buffer);
	}

	if (req->flags & ISCSI_FLAG_CMD_WRITE) {
		conn->rx_size = ntoh24(req->dlength);
		conn->rx_buffer = task->c_buffer;
		task->r2t_count = ntohl(req->data_length) - conn->rx_size;
		task->unsol_count = !(req->flags & ISCSI_FLAG_CMD_FINAL);
		task->offset = conn->rx_size;

		dprintf("%d %d %d %d\n", conn->rx_size, task->r2t_count,
			task->unsol_count, task->offset);
	}

	list_add(&task->c_hlist, &conn->session->cmd_list);
	return 0;
}

static int iscsi_noop_out_rx_start(struct iscsi_connection *conn)
{
	struct iscsi_hdr *req = (struct iscsi_hdr *) &conn->req.bhs;
	struct iscsi_task *task;
	int len, err = -ENOMEM;

	dprintf("%x %x %u\n", req->ttt, req->itt, ntoh24(req->dlength));
	if (req->ttt != cpu_to_be32(ISCSI_RESERVED_TAG)) {
		/*
		 * We don't request a NOP-Out by sending a NOP-In.
		 * See 10.18.2 in the draft 20.
		 */
		eprintf("initiator bug\n");
		err = -ISCSI_REASON_PROTOCOL_ERROR;
		goto out;
	}

	if (req->itt == cpu_to_be32(ISCSI_RESERVED_TAG)) {
		if (!(req->opcode & ISCSI_OP_IMMEDIATE)) {
			eprintf("initiator bug\n");
			err = -ISCSI_REASON_PROTOCOL_ERROR;
			goto out;
		}
	}

	conn->exp_stat_sn = be32_to_cpu(req->exp_statsn);

	task = iscsi_alloc_task(conn, 0);
	if (task)
		conn->rx_task = task;
	else
		goto out;

	len = ntoh24(req->dlength);
	if (len) {
		conn->rx_size = len;
		task->len = len;
		task->c_buffer = malloc(len);
		if (!task->c_buffer) {
			iscsi_free_task(task);
			goto out;
		}

		conn->rx_buffer = task->c_buffer;
	}
out:
	return err;
}

static int iscsi_task_rx_done(struct iscsi_connection *conn)
{
	struct iscsi_hdr *hdr = &conn->req.bhs;
	struct iscsi_task *task = conn->rx_task;
	uint8_t op;
	int err = 0;

	op = hdr->opcode & ISCSI_OPCODE_MASK;
	switch (op) {
	case ISCSI_OP_SCSI_CMD:
	case ISCSI_OP_NOOP_OUT:
	case ISCSI_OP_SCSI_TMFUNC:
	case ISCSI_OP_LOGOUT:
		err = iscsi_task_queue(task);
		break;
	case ISCSI_OP_SCSI_DATA_OUT:
		err = iscsi_data_out_rx_done(task);
		break;
	case ISCSI_OP_TEXT:
	case ISCSI_OP_SNACK:
	default:
		eprintf("Cannot handle yet %x\n", op);
		break;
	}

	conn->rx_task = NULL;
	return err;
}

static int iscsi_task_rx_start(struct iscsi_connection *conn)
{
	struct iscsi_hdr *hdr = &conn->req.bhs;
	struct iscsi_task *task;
	uint8_t op;
	int err = 0;

	op = hdr->opcode & ISCSI_OPCODE_MASK;
	switch (op) {
	case ISCSI_OP_SCSI_CMD:
		err = iscsi_scsi_cmd_rx_start(conn);
		if (!err)
			conn->exp_stat_sn = be32_to_cpu(hdr->exp_statsn);
		break;
	case ISCSI_OP_SCSI_DATA_OUT:
		err = iscsi_data_out_rx_start(conn);
		if (!err)
			conn->exp_stat_sn = be32_to_cpu(hdr->exp_statsn);
		break;
	case ISCSI_OP_NOOP_OUT:
		err = iscsi_noop_out_rx_start(conn);
		break;
	case ISCSI_OP_SCSI_TMFUNC:
	case ISCSI_OP_LOGOUT:
		task = iscsi_alloc_task(conn, 0);
		if (task)
			conn->rx_task = task;
		else
			err = -ENOMEM;
		break;
	case ISCSI_OP_TEXT:
	case ISCSI_OP_SNACK:
		eprintf("Cannot handle yet %x\n", op);
		err = -EINVAL;
		break;
	default:
		eprintf("Unknown op %x\n", op);
		err = -EINVAL;
		break;
	}

	return 0;
}

static int iscsi_scsi_cmd_tx_start(struct iscsi_task *task)
{
	int err = 0;
	struct iscsi_cmd *req = (struct iscsi_cmd *) &task->req;

	if (task->r2t_count)
		err = iscsi_r2t_build(task);
	else {
		/* Needs to clean up this mess. */

		if (req->flags & ISCSI_FLAG_CMD_WRITE)
			if (task->result)
				err = iscsi_sense_rsp_build(task);
			else
				err = iscsi_cmd_rsp_build(task);
		else {
			if (task->result)
				err = iscsi_sense_rsp_build(task);
			else if (task->len)
				err = iscsi_data_rsp_build(task);
			else
				err = iscsi_cmd_rsp_build(task);
		}
	}

	return err;
}

static int iscsi_logout_tx_start(struct iscsi_task *task)
{
	struct iscsi_connection *conn = task->conn;
	struct iscsi_logout_rsp *rsp =
		(struct iscsi_logout_rsp *) &conn->rsp.bhs;

	rsp->opcode = ISCSI_OP_LOGOUT_RSP;
	rsp->flags = ISCSI_FLAG_CMD_FINAL;
	rsp->itt = task->req.itt;
	rsp->statsn = cpu_to_be32(conn->stat_sn++);
	rsp->exp_cmdsn = cpu_to_be32(conn->session->exp_cmd_sn);
	rsp->max_cmdsn = cpu_to_be32(conn->session->exp_cmd_sn + MAX_QUEUE_CMD);

	return 0;
}

static int iscsi_noop_out_tx_start(struct iscsi_task *task, int *is_rsp)
{
	struct iscsi_connection *conn = task->conn;
	struct iscsi_data_rsp *rsp = (struct iscsi_data_rsp *) &conn->rsp.bhs;

	if (task->req.itt == cpu_to_be32(ISCSI_RESERVED_TAG)) {
		*is_rsp = 0;
		iscsi_free_task(task);
	} else {
		*is_rsp = 1;

		memset(rsp, 0, sizeof(*rsp));
		rsp->opcode = ISCSI_OP_NOOP_IN;
		rsp->flags = ISCSI_FLAG_CMD_FINAL;
		rsp->itt = task->req.itt;
		rsp->ttt = cpu_to_be32(ISCSI_RESERVED_TAG);
		rsp->statsn = cpu_to_be32(conn->stat_sn++);
		rsp->exp_cmdsn = cpu_to_be32(conn->session->exp_cmd_sn);
		rsp->max_cmdsn = cpu_to_be32(conn->session->exp_cmd_sn + MAX_QUEUE_CMD);

		/* TODO: honor max_burst */
		conn->rsp.datasize = task->len;
		hton24(rsp->dlength, task->len);
		conn->rsp.data = task->c_buffer;
	}

	return 0;
}

static int iscsi_tm_tx_start(struct iscsi_task *task)
{
	struct iscsi_connection *conn = task->conn;
	struct iscsi_tm_rsp *rsp = (struct iscsi_tm_rsp *) &conn->rsp.bhs;

	memset(rsp, 0, sizeof(*rsp));
	rsp->opcode = ISCSI_OP_SCSI_TMFUNC_RSP;
	rsp->flags = ISCSI_FLAG_CMD_FINAL;
	rsp->itt = task->req.itt;
	rsp->response = task->result;

	rsp->statsn = cpu_to_be32(conn->stat_sn++);
	rsp->exp_cmdsn = cpu_to_be32(conn->session->exp_cmd_sn);
	rsp->max_cmdsn = cpu_to_be32(conn->session->exp_cmd_sn + MAX_QUEUE_CMD);

	return 0;
}

static int iscsi_scsi_cmd_tx_done(struct iscsi_connection *conn)
{
	struct iscsi_hdr *hdr = &conn->rsp.bhs;
	struct iscsi_task *task = conn->tx_task;

	switch (hdr->opcode & ISCSI_OPCODE_MASK) {
	case ISCSI_OP_R2T:
		break;
	case ISCSI_OP_SCSI_DATA_IN:
		if (!(hdr->flags & ISCSI_FLAG_CMD_FINAL)) {
			dprintf("more data %x\n", hdr->itt);
			list_add_tail(&task->c_list, &task->conn->tx_clist);
			return 0;
		}
	case ISCSI_OP_SCSI_CMD_RSP:
		iscsi_free_cmd_task(task);
		break;
	default:
		eprintf("target bug %x\n", hdr->opcode & ISCSI_OPCODE_MASK);
	}

	return 0;
}

static int iscsi_task_tx_done(struct iscsi_connection *conn)
{
	struct iscsi_task *task = conn->tx_task;
	int err;

	switch (task->req.opcode & ISCSI_OPCODE_MASK) {
	case ISCSI_OP_SCSI_CMD:
		err = iscsi_scsi_cmd_tx_done(conn);
		break;
	case ISCSI_OP_NOOP_OUT:
	case ISCSI_OP_LOGOUT:
	case ISCSI_OP_SCSI_TMFUNC:
		iscsi_free_task(task);
	}

	conn->tx_task = NULL;
	return 0;
}

static int iscsi_task_tx_start(struct iscsi_connection *conn)
{
	struct iscsi_task *task;
	int is_rsp, err = 0;

	if (list_empty(&conn->tx_clist))
		goto nodata;

	conn_write_pdu(conn);

	task = list_entry(conn->tx_clist.next, struct iscsi_task, c_list);
	dprintf("found a task %" PRIx64 " %u %u %u\n", task->tag,
		ntohl(((struct iscsi_cmd *) (&task->req))->data_length),
		task->offset,
		task->r2t_count);

	list_del(&task->c_list);

	switch (task->req.opcode & ISCSI_OPCODE_MASK) {
	case ISCSI_OP_SCSI_CMD:
		err = iscsi_scsi_cmd_tx_start(task);
		break;
	case ISCSI_OP_NOOP_OUT:
		err = iscsi_noop_out_tx_start(task, &is_rsp);
		if (!is_rsp)
			goto nodata;
		break;
	case ISCSI_OP_LOGOUT:
		err = iscsi_logout_tx_start(task);
		break;
	case ISCSI_OP_SCSI_TMFUNC:
		err = iscsi_tm_tx_start(task);
		break;
	}

	conn->tx_task = task;
	return err;

nodata:
	dprintf("no more data\n");
	tgt_event_modify(conn->fd, EPOLLIN);
	return -EAGAIN;
}

static void iscsi_rx_handler(int fd, struct iscsi_connection *conn)
{
	int res;

	switch (conn->rx_iostate) {
	case IOSTATE_READ_BHS:
	case IOSTATE_READ_AHS_DATA:
	read_again:
		res = conn->tp->ep_read(fd, conn->rx_buffer, conn->rx_size);
		if (!res) {
			conn->state = STATE_CLOSE;
			break;
		} else if (res < 0) {
			if (errno == EINTR)
				goto read_again;
			else if (errno == EAGAIN)
				break;
			else {
				conn->state = STATE_CLOSE;
				dprintf("%d %d, %m\n", res, errno);
			}
			break;
		}
		conn->rx_size -= res;
		conn->rx_buffer += res;
		if (conn->rx_size)
			break;

		switch (conn->rx_iostate) {
		case IOSTATE_READ_BHS:
			conn->rx_iostate = IOSTATE_READ_AHS_DATA;
			conn->req.ahssize = conn->req.bhs.hlength * 4;
			conn->req.datasize = ntoh24(conn->req.bhs.dlength);
			conn->rx_size = (conn->req.ahssize + conn->req.datasize + 3) & -4;

			if (conn->req.ahssize) {
				eprintf("FIXME: we cannot handle ahs\n");
				conn->state = STATE_CLOSE;
				break;
			}

			if (conn->state == STATE_SCSI) {
				res = iscsi_task_rx_start(conn);
				if (res) {
					conn->state = STATE_CLOSE;
					break;
				}
			}

			if (conn->rx_size) {
				if (conn->state != STATE_SCSI) {
					conn->rx_buffer = conn->req_buffer;
					conn->req.ahs = conn->rx_buffer;
				}
				conn->req.data =
					conn->rx_buffer + conn->req.ahssize;
				goto read_again;
			}

		case IOSTATE_READ_AHS_DATA:
			if (conn->state == STATE_SCSI) {
				res = iscsi_task_rx_done(conn);
				if (!res)
					conn_read_pdu(conn);
			} else {
				conn_write_pdu(conn);
				tgt_event_modify(fd, EPOLLOUT);
				res = cmnd_execute(conn);
			}

			if (res)
				conn->state = STATE_CLOSE;
			break;
		}
		break;
	}
}

static void iscsi_tx_handler(int fd, struct iscsi_connection *conn)
{
	int res;

	if (conn->state == STATE_SCSI && !conn->tx_task) {
		res = iscsi_task_tx_start(conn);
		if (res)
			return;
	}

	switch (conn->tx_iostate) {
	case IOSTATE_WRITE_BHS:
	case IOSTATE_WRITE_AHS:
	case IOSTATE_WRITE_DATA:
	write_again:
		res = conn->tp->ep_write_begin(fd, conn->tx_buffer,
					       conn->tx_size);
		if (res < 0) {
			if (errno != EINTR && errno != EAGAIN)
				conn->state = STATE_CLOSE;
			else if (errno == EINTR)
				goto write_again;
			break;
		}

		conn->tx_size -= res;
		conn->tx_buffer += res;
		if (conn->tx_size)
			goto write_again;

		switch (conn->tx_iostate) {
		case IOSTATE_WRITE_BHS:
			if (conn->rsp.ahssize) {
				conn->tx_iostate = IOSTATE_WRITE_AHS;
				conn->tx_buffer = conn->rsp.ahs;
				conn->tx_size = conn->rsp.ahssize;
				goto write_again;
			}
		case IOSTATE_WRITE_AHS:
			if (conn->rsp.datasize) {
				int pad;

				conn->tx_iostate = IOSTATE_WRITE_DATA;
				conn->tx_buffer = conn->rsp.data;
				conn->tx_size = conn->rsp.datasize;
				pad = conn->tx_size & (PAD_WORD_LEN - 1);
				if (pad) {
					pad = PAD_WORD_LEN - pad;
					memset(conn->tx_buffer + conn->tx_size,
					       0, pad);
					conn->tx_size += pad;
				}
				goto write_again;
			}
		case IOSTATE_WRITE_DATA:
			conn->tp->ep_write_end(fd);
			cmnd_finish(conn);

			switch (conn->state) {
			case STATE_KERNEL:
				res = conn_take_fd(conn, fd);
				if (res)
					conn->state = STATE_CLOSE;
				else {
					conn->state = STATE_SCSI;
					conn_read_pdu(conn);
					tgt_event_modify(fd, EPOLLIN);
				}
				break;
			case STATE_EXIT:
			case STATE_CLOSE:
				break;
			case STATE_SCSI:
				iscsi_task_tx_done(conn);
				break;
			default:
				conn_read_pdu(conn);
				tgt_event_modify(fd, EPOLLIN);
				break;
			}
			break;
		}

		break;
	default:
		eprintf("illegal iostate %d %d\n", conn->tx_iostate,
			conn->tx_iostate);
		conn->state = STATE_CLOSE;
	}

}

void iscsi_event_handler(int fd, int events, void *data)
{
	struct iscsi_connection *conn = (struct iscsi_connection *) data;

	if (events & EPOLLIN)
		iscsi_rx_handler(fd, conn);

	if (conn->state == STATE_CLOSE)
		dprintf("connection closed\n");

	if (conn->state != STATE_CLOSE && events & EPOLLOUT)
		iscsi_tx_handler(fd, conn);

	if (conn->state == STATE_CLOSE)
		conn_close(conn, fd);
}
