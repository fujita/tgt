/*
 * Copyright (C) 2002-2003 Ardis Technolgies <roman@ardistech.com>
 *
 * Released under the terms of the GNU GPL v2.0.
 */

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "iscsid.h"

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

	if (!conn->rsp.datasize) {
		if (!conn->rsp_buffer)
			conn->rsp_buffer = malloc(INCOMING_BUFSIZE);
		conn->rsp.data = conn->rsp_buffer;
	}
	if (conn->rwsize + len > INCOMING_BUFSIZE) {
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

static int account_empty(u32 tid, int dir)
{
	char pass[ISCSI_NAME_LEN];

	memset(pass, 0, sizeof(pass));
	return cops->account_query(tid, dir, pass, pass) < 0 ? 1 : 0;
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
	int err;
	struct iscsi_login *req = (struct iscsi_login *)&conn->req.bhs;
	struct iscsi_login_rsp *rsp = (struct iscsi_login_rsp *) &conn->rsp.bhs;
	struct session *session;

	if (!conn->tid)
		return;

	if ((session = session_find_name(conn->tid, conn->initiator, req->isid))) {
		if (!req->tsih) {
			uint64_t sid = sid64(session->isid, session->tsih);
			/* do session reinstatement */
			session_conns_close(conn->tid, sid);
			session = NULL;
		} else if (req->tsih != session->tsih) {
			/* fail the login */
			rsp->status_class = ISCSI_STATUS_CLS_INITIATOR_ERR;
			rsp->status_detail = ISCSI_LOGIN_STATUS_TGT_NOT_FOUND;
			conn->state = STATE_EXIT;
			return;
		} else if ((err = conn_test(conn)) == -ENOENT) {
			/* do connection reinstatement */
		}
		/* add a new connection to the session */
		conn->session = session;
	} else {
		if (req->tsih) {
			/* fail the login */
			rsp->status_class = ISCSI_STATUS_CLS_INITIATOR_ERR;
			rsp->status_detail = ISCSI_LOGIN_STATUS_NO_SESSION;
			conn->state = STATE_EXIT;
			return;
		}
		/* instantiate a new session */
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

			if (idx == key_max_recv_data_length)
				idx = key_max_xmit_data_length;

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
				if (idx == key_max_xmit_data_length)
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
	struct iscsi_param *p = conn->session_param;
	char buf[32];
	int i, cnt;

	for (i = 0, cnt = 0; session_keys[i].name; i++) {
		if (p[i].state == KEY_STATE_START && p[i].val != session_keys[i].def) {
			if (conn->state == STATE_LOGIN) {
				if (i == key_max_xmit_data_length) {
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

		if (target_find_by_name(target_name, &conn->tid) < 0 ||
		    cops->initiator_access(conn->tid, conn->fd) < 0) {
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

		ki->param_get(conn->tid, 0, conn->session_param);
		conn->exp_cmd_sn = be32_to_cpu(req->cmdsn);
		log_debug(1, "exp_cmd_sn: %d,%d", conn->exp_cmd_sn, req->cmdsn);
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
                log_error("Unknown auth. method %d", conn->auth_method);
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
		log_debug(1, "Login request (security negotiation): %d", conn->state);
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
		log_debug(1, "Login request (operational negotiation): %d", conn->state);
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

	log_debug(1, "Text request: %d", conn->state);
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
	int res = 1;

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
		res = 0;
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
