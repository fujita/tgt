/*
 * (C) 2005 FUJITA Tomonori <tomof@acm.org>
 *
 * This code is licenced under the GPL.
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>

#include "iscsid.h"

int param_index_by_name(char *name, struct iscsi_key *keys)
{
	int i, err = -ENOENT;

	for (i = 0; keys[i].name; i++) {
		if (!strcasecmp(keys[i].name, name)) {
			err = i;
			break;
		}
	}

	return err;
}

void param_set_defaults(struct iscsi_param *params, struct iscsi_key *keys)
{
	int i;

	for (i = 0; keys[i].name; i++)
		params[i].val = keys[i].def;
}

static int range_val_to_str(unsigned int val, char *str)
{
	sprintf(str, "%u", val);
	return 0;
}

static int range_str_to_val(char *str, unsigned int *val)
{
	*val = strtol(str, NULL, 0);
	return 0;
}

static int bool_val_to_str(unsigned int val, char *str)
{
	int err = 0;

	switch (val) {
	case 0:
		strcpy(str, "No");
		break;
	case 1:
		strcpy(str, "Yes");
		break;
	default:
		err = -EINVAL;
	}

	return err;
}

static int bool_str_to_val(char *str, unsigned int *val)
{
	int err = 0;

	if (!strcmp(str, "Yes"))
		*val = 1;
	else if (!strcmp(str, "No"))
		*val = 0;
	else
		err = -EINVAL;

	return err;
}

static int or_set_val(struct iscsi_param *param, int idx, unsigned int *val)
{
	*val |= param[idx].val;
	param[idx].val = *val;

	return 0;
}

static int and_set_val(struct iscsi_param *param, int idx, unsigned int *val)
{
	*val &= param[idx].val;
	param[idx].val = *val;

	return 0;
}

static int minimum_check_val(struct iscsi_key *key, unsigned int *val)
{
	int err = 0;

	if (*val < key->min || key->max < *val) {
		*val = key->min;
		err = -EINVAL;
	}

	return 0;
}

static int maximum_check_val(struct iscsi_key *key, unsigned int *val)
{
	int err = 0;

	if (*val < key->min || key->max < *val) {
		*val = key->max;
		err = -EINVAL;
	}

	return 0;
}

static int minimum_set_val(struct iscsi_param *param, int idx, unsigned int *val)
{
	if (*val > param[idx].val)
		*val = param[idx].val;
	else
		param[idx].val = *val;

	return 0;
}

static int maximum_set_val(struct iscsi_param *param, int idx, unsigned int *val)
{
	if (param[idx].val > *val)
		*val = param[idx].val;
	else
		param[idx].val = *val;

	return 0;
}

static int digest_val_to_str(unsigned int val, char *str)
{
	int err = 0;

	if (val & DIGEST_CRC32C)
		strcpy(str, "CRC32C");
	else if (val & DIGEST_NONE)
		strcpy(str, "None");
	else
		err = -EINVAL;

	return err;
}

static int digest_str_to_val(char *str, unsigned int *val)
{
	int err = 0;
	char *p, *q;
	p = str;

	*val = DIGEST_NONE;
	do {
		if (!strncmp(p, "None", strlen("None")))
			*val |= DIGEST_NONE;
		else if (!strncmp(p, "CRC32C", strlen("CRC32C")))
			*val |= DIGEST_CRC32C;
		else {
			err = -EINVAL;
			break;
		}

		if ((q = strchr(p, ',')))
			p = q + 1;
	} while (q);

	return err;
}

static int digest_set_val(struct iscsi_param *param, int idx, unsigned int *val)
{
	if (*val & DIGEST_CRC32C && param[idx].val & DIGEST_CRC32C)
		*val = DIGEST_CRC32C;
	else
		*val = DIGEST_NONE;

	param[idx].val = *val;

	return 0;
}

static int marker_val_to_str(unsigned int val, char *str)
{
	if (val == 0)
		strcpy(str, "Irrelevant");
	else
		strcpy(str, "Reject");

	return 0;
}

static int marker_set_val(struct iscsi_param *param, int idx, unsigned int *val)
{
	if ((idx == key_ofmarkint && param[key_ofmarker].state == KEY_STATE_DONE) ||
	    (idx == key_ifmarkint && param[key_ifmarker].state == KEY_STATE_DONE))
		*val = 0;
	else
		*val = 1;

	param[idx].val = *val;

	return 0;
}

int param_val_to_str(struct iscsi_key *keys, int idx, unsigned int val, char *str)
{
	if (keys[idx].ops->val_to_str)
		return keys[idx].ops->val_to_str(val, str);
	else
		return 0;
}

int param_str_to_val(struct iscsi_key *keys, int idx, char *str, unsigned int *val)
{
	if (keys[idx].ops->str_to_val)
		return keys[idx].ops->str_to_val(str, val);
	else
		return 0;
}

int param_check_val(struct iscsi_key *keys, int idx, unsigned int *val)
{
	if (keys[idx].ops->check_val)
		return keys[idx].ops->check_val(&keys[idx], val);
	else
		return 0;
}

int param_set_val(struct iscsi_key *keys, struct iscsi_param *param,
		  int idx, unsigned int *val2)
{
	if (keys[idx].ops->set_val)
		return keys[idx].ops->set_val(param, idx, val2);
	else
		return 0;
}

static struct iscsi_key_ops minimum_ops = {
	.val_to_str = range_val_to_str,
	.str_to_val = range_str_to_val,
	.check_val = minimum_check_val,
	.set_val = minimum_set_val,
};

static struct iscsi_key_ops maximum_ops = {
	.val_to_str = range_val_to_str,
	.str_to_val = range_str_to_val,
	.check_val = maximum_check_val,
	.set_val = maximum_set_val,
};

static struct iscsi_key_ops or_ops = {
	.val_to_str = bool_val_to_str,
	.str_to_val = bool_str_to_val,
	.set_val = or_set_val,
};

static struct iscsi_key_ops and_ops = {
	.val_to_str = bool_val_to_str,
	.str_to_val = bool_str_to_val,
	.set_val = and_set_val,
};

static struct iscsi_key_ops digest_ops = {
	.val_to_str = digest_val_to_str,
	.str_to_val = digest_str_to_val,
	.set_val = digest_set_val,
};

static struct iscsi_key_ops marker_ops = {
	.val_to_str = marker_val_to_str,
	.set_val = marker_set_val,
};

#define	SET_KEY_VALUES(x)	DEFAULT_NR_##x,MIN_NR_##x, MAX_NR_##x

struct iscsi_key target_keys[] = {
	{"Wthreads", SET_KEY_VALUES(WTHREADS), &minimum_ops},
	{"Type", 0, 0, 16, &minimum_ops},
	{"QueuedCommands", SET_KEY_VALUES(QUEUED_CMNDS), &minimum_ops},
	{NULL,},
};

struct iscsi_key session_keys[] = {
	{"InitialR2T", 1, 0, 1, &or_ops},
	{"ImmediateData", 1, 0, 1, &and_ops},
	{"MaxConnections", 1, 1, 65535, &minimum_ops},
	{"MaxRecvDataSegmentLength", 8192, 512, 16777215, &minimum_ops},
	{"MaxXmitDataSegmentLength", 8192, 512, 16777215, &minimum_ops},
	{"MaxBurstLength", 262144, 512, 16777215, &minimum_ops},
	{"FirstBurstLength", 65536, 512, 16777215, &minimum_ops},
	{"DefaultTime2Wait", 2, 0, 3600, &maximum_ops},
	{"DefaultTime2Retain", 20, 0, 3600, &minimum_ops},
	{"MaxOutstandingR2T", 1, 1, 65535, &minimum_ops},
	{"DataPDUInOrder", 1, 0, 1, &or_ops},
	{"DataSequenceInOrder", 1, 0, 1, &or_ops},
	{"ErrorRecoveryLevel", 0, 0, 2, &minimum_ops},
	{"HeaderDigest", DIGEST_NONE, DIGEST_NONE, DIGEST_ALL, &digest_ops},
	{"DataDigest", DIGEST_NONE, DIGEST_NONE, DIGEST_ALL, &digest_ops},
	{"OFMarker", 0, 0, 1, &and_ops},
	{"IFMarker", 0, 0, 1, &and_ops},
	{"OFMarkInt", 2048, 1, 65535, &marker_ops},
	{"IFMarkInt", 2048, 1, 65535, &marker_ops},
	{NULL,},
};
