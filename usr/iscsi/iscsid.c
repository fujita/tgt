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
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <scsi/scsi.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "iscsid.h"
#include "tgtd.h"
#include "util.h"

static struct iscsi_key login_keys[] = {
	{"InitiatorName",},
	{"InitiatorAlias",},
	{"SessionType",},
	{"TargetName",},
	{NULL, 0, 0, 0, NULL},
};

char *text_key_find(struct connection *conn, char *searchKey)
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

void text_key_add(struct connection *conn, char *key, char *value)
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

static void text_key_add_reject(struct connection *conn, char *key)
{
	text_key_add(conn, key, "Reject");
}

static int account_empty(int tid, int dir)
{
	char pass[ISCSI_NAME_LEN];

	memset(pass, 0, sizeof(pass));
/* 	return cops->account_query(tid, dir, pass, pass) < 0 ? 1 : 0; */
	return 1;
}

static void text_scan_security(struct connection *conn)
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
					if (!account_empty(conn->tid, AUTH_DIR_INCOMING))
						continue;
					conn->auth_method = AUTH_NONE;
					text_key_add(conn, key, "None");
					break;
				} else if (!strcmp(value, "CHAP")) {
					if (account_empty(conn->tid, AUTH_DIR_INCOMING))
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

static void login_security_done(struct connection *conn)
{
	struct iscsi_login *req = (struct iscsi_login *)&conn->req.bhs;
	struct iscsi_login_rsp *rsp = (struct iscsi_login_rsp *) &conn->rsp.bhs;
	struct session *session;

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

static void text_scan_login(struct connection *conn)
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

static int text_check_param(struct connection *conn)
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

static void login_start(struct connection *conn)
{
	struct iscsi_login *req = (struct iscsi_login *)&conn->req.bhs;
	struct iscsi_login_rsp *rsp = (struct iscsi_login_rsp *)&conn->rsp.bhs;
	char *name, *alias, *session_type, *target_name;

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

/* 		if (target_find_by_name(target_name, &conn->tid) < 0 || */
/* 		    cops->initiator_access(conn->tid, conn->fd) < 0) { */
		if (target_find_by_name(target_name, &conn->tid) < 0) {
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

/* 		ki->param_get(conn->tid, 0, conn->session_param); */
		conn->exp_cmd_sn = be32_to_cpu(req->cmdsn);
		dprintf("exp_cmd_sn: %d,%d\n", conn->exp_cmd_sn, req->cmdsn);
		conn->max_cmd_sn = conn->exp_cmd_sn;
	}
	text_key_add(conn, "TargetPortalGroupTag", "1");
}

static void login_finish(struct connection *conn)
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

static int cmnd_exec_auth(struct connection *conn)
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

static void cmnd_exec_login(struct connection *conn)
{
	struct iscsi_login *req = (struct iscsi_login *)&conn->req.bhs;
	struct iscsi_login_rsp *rsp = (struct iscsi_login_rsp *)&conn->rsp.bhs;
	int stay = 0, nsg_disagree = 0;

	memset(rsp, 0, BHS_SIZE);
	if ((req->opcode & ISCSI_OPCODE_MASK) != ISCSI_OP_LOGIN ||
	    !(req->opcode & ISCSI_OP_IMMEDIATE)) {
		//reject
	}

	rsp->opcode = ISCSI_OP_LOGIN_RSP;
	rsp->max_version = ISCSI_DRAFT20_VERSION;
	rsp->active_version = ISCSI_DRAFT20_VERSION;
	rsp->itt = req->itt;

	if (/*req->max_version < ISCSI_VERSION ||*/
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
			//else fall through
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
			if (!account_empty(conn->tid, AUTH_DIR_INCOMING))
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

static void text_scan_text(struct connection *conn)
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

static void cmnd_exec_text(struct connection *conn)
{
	struct iscsi_text *req = (struct iscsi_text *)&conn->req.bhs;
	struct iscsi_text_rsp *rsp = (struct iscsi_text_rsp *)&conn->rsp.bhs;

	memset(rsp, 0, BHS_SIZE);

	if (be32_to_cpu(req->ttt) != 0xffffffff) {
		/* reject */;
	}
	rsp->opcode = ISCSI_OP_TEXT_RSP;
	rsp->itt = req->itt;
	//rsp->ttt = rsp->ttt;
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

static void cmnd_exec_logout(struct connection *conn)
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

int cmnd_execute(struct connection *conn)
{
	int res = 0;

	switch (conn->req.bhs.opcode & ISCSI_OPCODE_MASK) {
	case ISCSI_OP_LOGIN:
		//if conn->state == STATE_FULL -> reject
		cmnd_exec_login(conn);
		conn->rsp.bhs.hlength = conn->rsp.ahssize / 4;
		hton24(conn->rsp.bhs.dlength, conn->rsp.datasize);
		log_pdu(2, &conn->rsp);
		break;
	case ISCSI_OP_TEXT:
		//if conn->state != STATE_FULL -> reject
		cmnd_exec_text(conn);
		conn->rsp.bhs.hlength = conn->rsp.ahssize / 4;
		hton24(conn->rsp.bhs.dlength, conn->rsp.datasize);
		log_pdu(2, &conn->rsp);
		break;
	case ISCSI_OP_LOGOUT:
		//if conn->state != STATE_FULL -> reject
		cmnd_exec_logout(conn);
		conn->rsp.bhs.hlength = conn->rsp.ahssize / 4;
		hton24(conn->rsp.bhs.dlength, conn->rsp.datasize);
		log_pdu(2, &conn->rsp);
		break;
	default:
		//reject
		res = 1;
		break;
	}

	return res;
}

void cmnd_finish(struct connection *conn)
{
	switch (conn->state) {
	case STATE_EXIT:
		conn->state = STATE_CLOSE;
		break;
	case STATE_SECURITY_LOGIN:
		conn->state = STATE_LOGIN;
		break;
	case STATE_SECURITY_FULL:
		//fall through
	case STATE_LOGIN_FULL:
		if (conn->session_type == SESSION_NORMAL)
			conn->state = STATE_KERNEL;
		else
			conn->state = STATE_FULL;
		break;
	}
}

static int iscsi_cmd_rsp_build(struct iscsi_ctask *ctask)
{
	struct connection *conn = ctask->conn;
	struct iscsi_cmd_rsp *rsp = (struct iscsi_cmd_rsp *) &conn->rsp.bhs;

	memset(rsp, 0, sizeof(*rsp));
	rsp->opcode = ISCSI_OP_SCSI_CMD_RSP;
	rsp->itt = ctask->tag;
	rsp->flags = ISCSI_FLAG_CMD_FINAL;
	rsp->response = ISCSI_STATUS_CMD_COMPLETED;
	rsp->cmd_status = ctask->result;
	rsp->statsn = cpu_to_be32(conn->stat_sn++);
	rsp->exp_cmdsn = cpu_to_be32(conn->exp_cmd_sn);
	rsp->max_cmdsn = cpu_to_be32(conn->exp_cmd_sn + 8);

	return 0;
}

static int iscsi_data_rsp_build(struct iscsi_ctask *ctask)
{
	struct connection *conn = ctask->conn;
	struct iscsi_data_rsp *rsp = (struct iscsi_data_rsp *) &conn->rsp.bhs;
	struct iscsi_cmd *req = (struct iscsi_cmd *) &ctask->req;
	int residual, datalen, exp_datalen = ntohl(req->data_length);
	int max_burst = conn->session_param[ISCSI_PARAM_MAX_XMIT_DLENGTH].val;

	memset(rsp, 0, sizeof(*rsp));
	rsp->opcode = ISCSI_OP_SCSI_DATA_IN;
	rsp->itt = ctask->tag;
	rsp->ttt = cpu_to_be32(ISCSI_RESERVED_TAG);
	rsp->cmd_status = ISCSI_STATUS_CMD_COMPLETED;

	rsp->offset = cpu_to_be32(ctask->offset);
	rsp->datasn = cpu_to_be32(ctask->data_sn++);
	rsp->cmd_status = ctask->result;

	datalen = min(exp_datalen, ctask->len);
	datalen -= ctask->offset;

	dprintf("%d %d %d %d %x\n", datalen, exp_datalen, ctask->len, max_burst, rsp->itt);

	if (datalen <= max_burst) {
		rsp->flags = ISCSI_FLAG_CMD_FINAL | ISCSI_FLAG_DATA_STATUS;
		if (ctask->len < exp_datalen) {
			rsp->flags |= ISCSI_FLAG_CMD_UNDERFLOW;
			residual = exp_datalen - ctask->len;
		} else if (ctask->len > exp_datalen) {
			rsp->flags |= ISCSI_FLAG_CMD_OVERFLOW;
			residual = ctask->len - exp_datalen;
		} else
			residual = 0;
		rsp->residual_count = cpu_to_be32(residual);
	} else
		datalen = max_burst;

	if (rsp->flags & ISCSI_FLAG_CMD_FINAL)
		rsp->statsn = cpu_to_be32(conn->stat_sn++);
	rsp->exp_cmdsn = cpu_to_be32(conn->exp_cmd_sn);
	rsp->max_cmdsn = cpu_to_be32(conn->exp_cmd_sn + 8);

	conn->rsp.datasize = datalen;
	hton24(rsp->dlength, datalen);
	conn->rsp.data = (void *) (unsigned long) ctask->addr;
	conn->rsp.data += ctask->offset;

	ctask->offset += datalen;

	return 0;
}

static int iscsi_r2t_build(struct iscsi_ctask *ctask)
{
	struct connection *conn = ctask->conn;
	struct iscsi_r2t_rsp *rsp = (struct iscsi_r2t_rsp *) &conn->rsp.bhs;
	int length, max_burst = conn->session_param[ISCSI_PARAM_MAX_XMIT_DLENGTH].val;

	memset(rsp, 0, sizeof(*rsp));

	rsp->opcode = ISCSI_OP_R2T;
	rsp->flags = ISCSI_FLAG_CMD_FINAL;
	memcpy(rsp->lun, ctask->req.lun, sizeof(rsp->lun));

	rsp->itt = ctask->req.itt;
	rsp->r2tsn = cpu_to_be32(ctask->exp_r2tsn++);
	rsp->data_offset = cpu_to_be32(ctask->offset);
	rsp->ttt = (unsigned long) ctask;
	length = min(ctask->r2t_count, max_burst);
	rsp->data_length = cpu_to_be32(length);
	ctask->r2t_count -= length;

	return 0;
}

int iscsi_cmd_done(int host_no, int len, int result, int rw, uint64_t addr,
		   uint64_t tag)
{
	struct session *session;
	struct iscsi_ctask *ctask;

	dprintf("%u %d %d %d %" PRIx64 " %" PRIx64 "\n", host_no, len, result,
		rw, addr, tag);
	session = session_lookup(host_no);
	if (!session)
		return -EINVAL;

	list_for_each_entry(ctask, &session->cmd_list, c_hlist) {
		if (ctask->tag == tag)
			goto found;
	}
	eprintf("Cannot find a task %" PRIx64 "\n", tag);
	return -EINVAL;

found:
	eprintf("found a task %" PRIx64 "\n", tag);
	ctask->addr = addr;
	ctask->result = result;
	ctask->len = len;
	ctask->rw = rw;

	list_add_tail(&ctask->c_txlist, &ctask->conn->tx_clist);
	tgt_event_modify(ctask->conn->fd, EPOLLIN|EPOLLOUT);

	return 0;
}

static int iscsi_data_out_rx_start(struct connection *conn)
{
	struct iscsi_ctask *ctask;
	struct iscsi_data *req = (struct iscsi_data *) &conn->req.bhs;

	list_for_each_entry(ctask, &conn->session->cmd_list, c_hlist) {
		if (ctask->tag == req->itt)
			goto found;
	}
	return -EINVAL;
found:
	eprintf("found a task %" PRIx64 " %u %u %u %u %u\n", ctask->tag,
		ntohl(((struct iscsi_cmd *) (&ctask->req))->data_length),
		ctask->offset,
		ctask->r2t_count,
		ntoh24(req->dlength), be32_to_cpu(req->offset));

/* 	conn->rx_buffer = (void *) (unsigned long) ctask->addr; */
	conn->rx_buffer = (void *) (unsigned long) ctask->c_buffer;
	conn->rx_buffer += be32_to_cpu(req->offset);
	conn->rx_size = ntoh24(req->dlength);

	ctask->offset += ntoh24(req->dlength);

	conn->rx_ctask = ctask;

	return 0;
}

static int iscsi_cmd_init(struct connection *conn)
{
	struct iscsi_cmd *req = (struct iscsi_cmd *) &conn->req.bhs;
	struct iscsi_ctask *ctask;
	int len;

	ctask = zalloc(sizeof(*ctask));
	if (!ctask)
		return -ENOMEM;

	memcpy(&ctask->req, req, sizeof(*req));
	ctask->tag = req->itt;
	ctask->conn = conn;
	INIT_LIST_HEAD(&ctask->c_hlist);

	list_add(&ctask->c_hlist, &conn->session->cmd_list);

	dprintf("%u %x %d %d %x\n", conn->session->tsih,
		req->cdb[0], ntohl(req->data_length),
		req->flags & ISCSI_FLAG_CMD_ATTR_MASK, req->itt);

	len = ntohl(req->data_length);
	if (len) {
		ctask->c_buffer = malloc(len);
		if (!ctask->c_buffer)
			return -ENOMEM;
		dprintf("%p\n", ctask->c_buffer);
	}

	conn->exp_cmd_sn++;
	conn->rx_ctask = ctask;

	if (req->flags & ISCSI_FLAG_CMD_WRITE) {
		conn->rx_size = ntoh24(req->dlength);
		conn->rx_buffer = ctask->c_buffer;
		ctask->r2t_count = ntohl(req->data_length) - conn->rx_size;
		ctask->unsol_count = !(req->flags & ISCSI_FLAG_CMD_FINAL);
		ctask->offset = conn->rx_size;

		dprintf("%d %d %d %d\n", conn->rx_size, ctask->r2t_count,
			ctask->unsol_count, ctask->offset);
	}

	return 0;
}

int cmd_attr(struct iscsi_ctask *ctask)
{
	int attr;
	struct iscsi_cmd *req = (struct iscsi_cmd *) &ctask->req;

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

static int __iscsi_cmd_rx_done(struct iscsi_ctask *ctask)
{
	struct connection *conn = ctask->conn;
	struct iscsi_cmd *req = (struct iscsi_cmd *) &ctask->req;
	unsigned long uaddr = (unsigned long) ctask->c_buffer;
	int err = 0;

	if (req->flags & ISCSI_FLAG_CMD_WRITE) {
		if (ctask->r2t_count) {
			if (ctask->unsol_count)
				;
			else
				list_add_tail(&ctask->c_txlist, &ctask->conn->tx_clist);
		} else
			err = target_cmd_queue(conn->session->tsih, req->cdb,
					       uaddr, req->lun,
					       ntohl(req->data_length),
					       cmd_attr(ctask), req->itt);

	} else
		err = target_cmd_queue(conn->session->tsih, req->cdb,
				       uaddr, req->lun, ntohl(req->data_length),
				       cmd_attr(ctask), req->itt);

	tgt_event_modify(conn->fd, EPOLLIN|EPOLLOUT);

	return err;
}

int iscsi_cmd_rx_done(struct connection *conn)
{
	struct iscsi_hdr *hdr = &conn->req.bhs;
	struct iscsi_ctask *ctask = conn->rx_ctask;
	struct iscsi_cmd *req = (struct iscsi_cmd *) &ctask->req;
	uint8_t op;
	int err = 0;

	op = hdr->opcode & ISCSI_OPCODE_MASK;
	switch (op) {
	case ISCSI_OP_SCSI_CMD:
		__iscsi_cmd_rx_done(ctask);
		break;
	case ISCSI_OP_SCSI_DATA_OUT:
		if (ctask->r2t_count) {
			dprintf("%x %d\n", hdr->itt, ctask->r2t_count);
			list_add_tail(&ctask->c_txlist, &ctask->conn->tx_clist);
			tgt_event_modify(conn->fd, EPOLLIN|EPOLLOUT);
		} else
			err = target_cmd_queue(conn->session->tsih, req->cdb,
					       (unsigned long) ctask->c_buffer,
					       req->lun,
					       ntohl(req->data_length),
					       cmd_attr(ctask), req->itt);
		break;
	case ISCSI_OP_NOOP_OUT:
	case ISCSI_OP_SCSI_TMFUNC:
	case ISCSI_OP_LOGOUT:
	case ISCSI_OP_TEXT:
	case ISCSI_OP_SNACK:
	default:
		eprintf("Cannot handle yet %x\n", op);
		break;
	}

	conn->rx_ctask = NULL;
	return err;
}

int iscsi_cmd_rx_start(struct connection *conn)
{
	struct iscsi_hdr *hdr = &conn->req.bhs;
	uint8_t op;
	int err;

	op = hdr->opcode & ISCSI_OPCODE_MASK;
	switch (op) {
	case ISCSI_OP_SCSI_CMD:
		err = iscsi_cmd_init(conn);
		if (!err)
			conn->exp_stat_sn = be32_to_cpu(hdr->exp_statsn);
		break;
	case ISCSI_OP_SCSI_DATA_OUT:
		err = iscsi_data_out_rx_start(conn);
		if (!err)
			conn->exp_stat_sn = be32_to_cpu(hdr->exp_statsn);
		break;
	case ISCSI_OP_NOOP_OUT:
	case ISCSI_OP_SCSI_TMFUNC:
	case ISCSI_OP_LOGOUT:
	case ISCSI_OP_TEXT:
	case ISCSI_OP_SNACK:
		eprintf("Cannot handle yet %x\n", op);
		err = -EINVAL;
	default:
		eprintf("Unknown op %x\n", op);
		err = -EINVAL;
		break;
	}

	return 0;
}

int iscsi_cmd_tx_done(struct connection *conn)
{
	struct iscsi_hdr *hdr = &conn->rsp.bhs;
	struct iscsi_ctask *ctask = conn->tx_ctask;

	switch (hdr->opcode & ISCSI_OPCODE_MASK) {
	case ISCSI_OP_R2T:
		break;
	case ISCSI_OP_SCSI_DATA_IN:
		if (!(hdr->flags & ISCSI_FLAG_CMD_FINAL)) {
			dprintf("more data %x\n", hdr->itt);
			list_add_tail(&ctask->c_txlist, &ctask->conn->tx_clist);
			goto out;
		}
	default:
		target_cmd_done(conn->session->tsih, ctask->tag);
		list_del(&ctask->c_hlist);
		if (ctask->c_buffer) {
			if ((unsigned long) ctask->c_buffer != ctask->addr)
				free((void *) (unsigned long) ctask->addr);
			free(ctask->c_buffer);
		}
		free(ctask);
	}

out:
	conn->tx_ctask = NULL;
	return 0;
}

int iscsi_cmd_tx_start(struct connection *conn)
{
	struct iscsi_ctask *ctask;
	struct iscsi_cmd *req;
	int err = 0;

	if (list_empty(&conn->tx_clist)) {
		dprintf("no more data\n");
		tgt_event_modify(conn->fd, EPOLLIN);
		return -EAGAIN;
	}

	conn_write_pdu(conn);

	ctask = list_entry(conn->tx_clist.next, struct iscsi_ctask, c_txlist);
	conn->tx_ctask = ctask;
	eprintf("found a task %" PRIx64 " %u %u %u\n", ctask->tag,
		ntohl(((struct iscsi_cmd *) (&ctask->req))->data_length),
		ctask->offset,
		ctask->r2t_count);

	list_del(&ctask->c_txlist);

	req = (struct iscsi_cmd *) &ctask->req;

	if (ctask->r2t_count)
		iscsi_r2t_build(ctask);
	else {
		if (req->flags & ISCSI_FLAG_CMD_WRITE)
			err = iscsi_cmd_rsp_build(ctask);
		else {
			if (ctask->len)
				err = iscsi_data_rsp_build(ctask);
			else
				err = iscsi_cmd_rsp_build(ctask);
		}
	}

	return err;
}
