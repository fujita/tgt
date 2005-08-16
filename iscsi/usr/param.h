/*
 * (C) 2005 FUJITA Tomonori <tomof@acm.org>
 *
 * This code is licenced under the GPL.
 */

#ifndef PARAMS_H
#define PARAMS_H

struct iscsi_key;

struct iscsi_param {
	int state;
	unsigned int val;
};

struct iscsi_key_ops {
	int (*val_to_str)(unsigned int, char *);
	int (*str_to_val)(char *, unsigned int *);
	int (*check_val)(struct iscsi_key *, unsigned int *);
	int (*set_val)(struct iscsi_param *, int, unsigned int *);
};

struct iscsi_key {
	char *name;
	unsigned int def;
	unsigned int min;
	unsigned int max;
	struct iscsi_key_ops *ops;
};

extern struct iscsi_key session_keys[];
extern struct iscsi_key target_keys[];

extern void param_set_defaults(struct iscsi_param *, struct iscsi_key *);
extern int param_index_by_name(char *, struct iscsi_key *);
extern int param_val_to_str(struct iscsi_key *, int, unsigned int, char *);
extern int param_str_to_val(struct iscsi_key *, int, char *, unsigned int *);
extern int param_check_val(struct iscsi_key *, int, unsigned int *);
extern int param_set_val(struct iscsi_key *, struct iscsi_param *, int, unsigned int *);

#endif
