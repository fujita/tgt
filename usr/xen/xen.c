#include <string.h>
#include <sys/epoll.h>
#include <xs.h>

#include "list.h"
#include "util.h"
#include "tgtd.h"
#include "driver.h"
#include "xs_api.h"

/* xenstore/xenbus: */
extern int add_blockdevice_probe_watch(struct xs_handle *h,
                                       const char *domname);
extern int xs_fire_next_watch(struct xs_handle *h);

static void xen_event_handle(int fd, int events, void *data)
{
	xs_fire_next_watch((struct xs_handle *) data);
}

static int xen_init(int index)
{
	int err;
	struct xs_handle *xsh;

	xsh = xs_daemon_open();
	if (!xsh) {
		eprintf("xs_daemon_open\n");
		goto open_failed;
	}

	err = add_blockdevice_probe_watch(xsh, "Domain-0");
	if (err) {
		eprintf("adding device probewatch\n");
		goto open_failed;
	}

	err = tgt_event_add(xs_fileno(xsh), EPOLLIN, xen_event_handle, xsh);

	return 0;

open_failed:
	return -1;
}

struct tgt_driver xen = {
	.name			= "xen",
	.use_kernel		= 1,
	.init			= xen_init,
	.cmd_end_notify		= kspace_send_cmd_res,
	.mgmt_end_notify	= kspace_send_tsk_mgmt_res,
	.default_bst		= &xen_bst,
};
