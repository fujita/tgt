#include <errno.h>
#include <string.h>
#include <inttypes.h>

#include "list.h"
#include "tgtd.h"
#include "driver.h"

#ifdef IBMVIO
#include "ibmvio/ibmvio.h"
#endif

#ifdef ISCSI
#include "iscsi/iscsi.h"
#endif

struct tgt_driver *tgt_drivers[] = {
#ifdef IBMVIO
	&ibmvio,
#endif
#ifdef ISCSI
	&iscsi,
#endif
	NULL,
};

int get_driver_index(char *name)
{
	int i;

	for (i = 0; tgt_drivers[i]; i++) {
		if (!strcmp(name, tgt_drivers[i]->name))
			return i;
	}

	return -ENOENT;
}
