#include <errno.h>
#include <string.h>
#include <poll.h>
#include <inttypes.h>

#include "tgtd.h"
#include "driver.h"

#ifdef ISCSI
#include "iscsi/iscsi.h"
#endif

#ifdef IBMVIO
struct tgt_driver ibmvio = {
	.name	= "ibmvio",
};
#endif

#ifdef ISCSI
struct tgt_driver iscsi = {
	.name		= "iscsi",
	.init		= iscsi_init,
	.poll_init	= iscsi_poll_init,
	.event_handle	= iscsi_event_handle,
	.target_create	= iscsi_target_create,
	.target_destroy	= iscsi_target_destroy,
	.target_bind	= iscsi_target_bind,
};
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
