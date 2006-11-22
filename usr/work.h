#ifndef __SCHED_H
#define __SCHED_H

#define SCHED_HZ 5

struct tgt_work {
	struct list_head entry;
	void (*func)(void *);
	void *data;
	unsigned int when;
};

extern void schedule(void);
extern void enqueue_work(struct tgt_work *work, unsigned int second);
extern void dequeue_work(struct tgt_work *work);

extern int stop_daemon;

#endif
