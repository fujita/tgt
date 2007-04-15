#ifndef __SCHED_H
#define __SCHED_H

#define TGTD_TICK_PERIOD 2

struct tgt_work {
	struct list_head entry;
	void (*func)(void *);
	void *data;
	unsigned int when;
};

extern void schedule(void);
extern void add_work(struct tgt_work *work, unsigned int second);
extern void del_work(struct tgt_work *work);

#endif
