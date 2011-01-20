#ifndef __SCHED_H
#define __SCHED_H

#include <sys/time.h>

struct tgt_work {
	struct list_head entry;
	void (*func)(void *);
	void *data;
	unsigned int when;
};

extern int work_timer_start(void);
extern void work_timer_stop(void);

extern void add_work(struct tgt_work *work, unsigned int second);
extern void del_work(struct tgt_work *work);

#endif
