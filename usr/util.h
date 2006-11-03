#ifndef __UTIL_H__
#define __UTIL_H__

#include <sys/user.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define ALIGN(x,a) (((x)+(a)-1)&~((a)-1))

#ifndef PAGE_SHIFT
#define	PAGE_SHIFT	12
#define	PAGE_SIZE	(1UL << PAGE_SHIFT)
#define	PAGE_MASK	(~(PAGE_SIZE-1))
#endif

#define pgcnt(size, offset)	((((size) + ((offset) & ~PAGE_MASK)) + PAGE_SIZE - 1) >> PAGE_SHIFT)

#define	DEFDMODE	(S_IRUSR|S_IWUSR|S_IXUSR|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH)
#define	DEFFMODE	(S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH)

#define min(x,y) ({ \
	typeof(x) _x = (x);	\
	typeof(y) _y = (y);	\
	(void) (&_x == &_y);		\
	_x < _y ? _x : _y; })

#define max(x,y) ({ \
	typeof(x) _x = (x);	\
	typeof(y) _y = (y);	\
	(void) (&_x == &_y);		\
	_x > _y ? _x : _y; })

#define min_t(type,x,y) \
	({ type __x = (x); type __y = (y); __x < __y ? __x: __y; })
#define max_t(type,x,y) \
	({ type __x = (x); type __y = (y); __x > __y ? __x: __y; })

extern int chrdev_open(char *modname, char *devpath, uint8_t minor, int *fd);
extern int backed_file_open(char *path, int oflag, uint64_t *size);

#define zalloc(size)			\
({					\
	void *ptr = malloc(size);	\
	if (ptr)			\
		memset(ptr, 0, size);	\
	else				\
		eprintf("%m\n");	\
	ptr;				\
})

static inline int before(uint32_t seq1, uint32_t seq2)
{
        return (int32_t)(seq1 - seq2) < 0;
}

static inline int after(uint32_t seq1, uint32_t seq2)
{
	return (int32_t)(seq2 - seq1) < 0;
}

/* is s2<=s1<=s3 ? */
static inline int between(uint32_t seq1, uint32_t seq2, uint32_t seq3)
{
	return seq3 - seq2 >= seq1 - seq2;
}

#endif
