#include <sys/user.h>

/* taken from linux kernel */

#undef offsetof
#ifdef __compiler_offsetof
#define offsetof(TYPE,MEMBER) __compiler_offsetof(TYPE,MEMBER)
#else
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

#define LIST_HEAD_INIT(name) { &(name), &(name) }

#define INIT_LIST_HEAD(ptr) do { \
	(ptr)->q_forw = (ptr); (ptr)->q_back = (ptr); \
} while (0)

#define container_of(ptr, type, member) ({			\
        const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
        (type *)( (char *)__mptr - offsetof(type,member) );})

#define list_entry(ptr, type, member) \
	container_of(ptr, type, member)

#define list_for_each(pos, head) \
	for (pos = (head)->q_forw; pos != (head); pos = pos->q_forw)

#define list_for_each_entry(pos, head, member)				\
	for (pos = list_entry((head)->q_forw, typeof(*pos), member);	\
	     &pos->member != (head); 	\
	     pos = list_entry(pos->member.q_forw, typeof(*pos), member))

#ifndef PAGE_SHIFT
#define	PAGE_SHIFT	12
#define	PAGE_SIZE	(1UL << PAGE_SHIFT)
#define	PAGE_MASK	(~(PAGE_SIZE-1))
#endif

#define pgcnt(size, offset)	((((size) + ((offset) & ~PAGE_MASK)) + PAGE_SIZE - 1) >> PAGE_SHIFT)

struct qelem {
	struct qelem *q_forw;
	struct qelem *q_back;
};
