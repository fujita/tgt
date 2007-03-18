#include <errno.h>
#include <string.h>
#include <inttypes.h>

#include "list.h"
#include "tgtd.h"
#include "driver.h"

extern struct tgt_driver ibmvio, iscsi, xen;

struct tgt_driver *tgt_drivers[] = {
#ifdef IBMVIO
	&ibmvio,
#endif
#ifdef ISCSI
	&iscsi,
#endif
#ifdef XEN
	&xen,
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
