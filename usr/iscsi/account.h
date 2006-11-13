#ifndef ACCOUNT_H
#define ACCOUNT_H

struct ac_node;

struct ac_head {
	struct ac_node *first;
};

struct ac_node {
	struct ac_node *next;
	struct ac_head *head;
};

extern int iscsi_account_lookup(int tid, int dir, char *user, char *pass);
extern int iscsi_account_available(int tid, int dir);

#endif

