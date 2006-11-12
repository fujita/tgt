#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>

#include "transport.h"

struct iscsi_transport *iscsi_transports[] = {
	&iscsi_tcp,
	NULL,
};

int iscsi_init(void)
{
	int i, err, nr = 0;

	for (i = 0; iscsi_transports[i]; i++) {
		err = iscsi_transports[i]->ep_init();
		if (!err)
			nr++;
	}
	return !nr;
}
