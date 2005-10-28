#ifndef __TGT_TYPES_H
#define __TGT_TYPES_H

#include <linux/types.h>

/* taken from inttypes.h */

#if BITS_PER_LONG == 64
#  define __PRI64_PREFIX	"l"
# else
#  define __PRI64_PREFIX	"ll"
# endif

# define PRId64		__PRI64_PREFIX "d"
# define PRIu64		__PRI64_PREFIX "u"
# define PRIx64		__PRI64_PREFIX "x"

#endif
