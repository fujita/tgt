#ifndef __UTIL_H__
#define __UTIL_H__

#include <byteswap.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <syscall.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <linux/types.h>

#include "be_byteshift.h"

#define roundup(x, y) ((((x) + ((y) - 1)) / (y)) * (y))
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define ALIGN(x,a) (((x)+(a)-1)&~((a)-1))

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define __cpu_to_be16(x) bswap_16(x)
#define __cpu_to_be32(x) bswap_32(x)
#define __cpu_to_be64(x) bswap_64(x)
#define __be16_to_cpu(x) bswap_16(x)
#define __be32_to_cpu(x) bswap_32(x)
#define __be64_to_cpu(x) bswap_64(x)
#define __cpu_to_le32(x) (x)
#else
#define __cpu_to_be16(x) (x)
#define __cpu_to_be32(x) (x)
#define __cpu_to_be64(x) (x)
#define __be16_to_cpu(x) (x)
#define __be32_to_cpu(x) (x)
#define __be64_to_cpu(x) (x)
#define __cpu_to_le32(x) bswap_32(x)
#endif

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

extern int get_blk_shift(unsigned int size);
extern int chrdev_open(char *modname, char *devpath, uint8_t minor, int *fd);
extern int backed_file_open(char *path, int oflag, uint64_t *size);
extern int set_non_blocking(int fd);
extern int str_to_open_flags(char *buf);
extern char *open_flags_to_str(char *dest, int flags);

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

extern unsigned long pagesize, pageshift;

#if defined(__NR_signalfd) && defined(USE_SIGNALFD)

/*
 * workaround for broken linux/signalfd.h including
 * usr/include/linux/fcntl.h
 */
#define _LINUX_FCNTL_H

#include <linux/signalfd.h>

static inline int __signalfd(int fd, const sigset_t *mask, int flags)
{
	int fd2, ret;

	fd2 = syscall(__NR_signalfd, fd, mask, _NSIG / 8);
	if (fd2 < 0)
		return fd2;

	ret = fcntl(fd2, F_GETFL);
	if (ret < 0) {
		close(fd2);
		return -1;
	}

	ret = fcntl(fd2, F_SETFL, ret | O_NONBLOCK);
	if (ret < 0) {
		close(fd2);
		return -1;
	}

	return fd2;
}
#else
#define __signalfd(fd, mask, flags) (-1)
struct signalfd_siginfo {
};
#endif

#define str_to_int(str, val, minv, maxv)		\
({							\
	char *ptr;					\
	int ret = 0;					\
	val = (typeof(val)) strtoull(str, &ptr, 0);	\
	if (errno || ptr == str) 			\
		ret = EINVAL;				\
	else if (val < minv || val > maxv)		\
		ret = ERANGE;				\
	ret;						\
})

struct concat_buf {
	FILE *streamf;
	int err;
	int used;
	char *buf;
	int size;
};

static inline void concat_buf_init(struct concat_buf *b)
{
	b->streamf = open_memstream(&b->buf, (size_t *)&b->size);
	b->err = b->streamf ? 0 : errno;
	b->used = 0;
}

static inline int concat_printf(struct concat_buf *b, const char *format, ...)
{
	va_list args;
	int nprinted;

	if (!b->err) {
		va_start(args, format);
		nprinted = vfprintf(b->streamf, format, args);
		if (nprinted >= 0)
			b->used += nprinted;
		else {
			b->err = nprinted;
			fclose(b->streamf);
			b->streamf = NULL;
		}
		va_end(args);
	}
	return b->err;
}

static inline const char *concat_delim(struct concat_buf *b, const char *delim)
{
	return !b->used ? "" : delim;
}

static inline int concat_buf_finish(struct concat_buf *b)
{
	if (b->streamf) {
		fclose(b->streamf);
		b->streamf = NULL;
		if (b->size)
			b->size ++; /* account for trailing NULL char */
	}
	return b->err;
}

static inline int concat_write(struct concat_buf *b, int fd, int offset)
{
	concat_buf_finish(b);

	if (b->err)
		return b->err;

	if (b->size - offset > 0)
		return write(fd, b->buf + offset, b->size - offset);
	else
		return 0;
}

static inline void concat_buf_release(struct concat_buf *b)
{
	concat_buf_finish(b);
	if (b->buf) {
		free(b->buf);
		memset(b, 0, sizeof(*b));
	}
}

#endif
