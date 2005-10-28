#ifndef __TGT_TYPES_H
#define __TGT_TYPES_H

#include <linux/types.h>

/* Is there a smart way? */

#if defined(CONFIG_ALPAH) || defined(CONFIG_IA64) || defined(CONFIG_PPC64) || (defined(CONFIG_S390) && defined(__x390x__)) || defined(CONFIG_SPARC64)
#  define __PRI64_PREFIX	"l"
# else
#  define __PRI64_PREFIX	"ll"
# endif

# define PRId64		__PRI64_PREFIX "d"
# define PRIu64		__PRI64_PREFIX "u"
# define PRIx64		__PRI64_PREFIX "x"


#define DEBUG_TGT

#define eprintk(fmt, args...)					\
do {								\
	printk("%s(%d) " fmt, __FUNCTION__, __LINE__, args);	\
} while (0)

#ifdef DEBUG_TGT
#define dprintk eprintk
#else
#define dprintk(fmt, args...)
#endif

#endif
