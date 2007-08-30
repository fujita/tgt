/*
 * driver routine
 *
 * Copyright (C) 2007 FUJITA Tomonori <tomof@acm.org>
 * Copyright (C) 2007 Mike Christie <michaelc@cs.wisc.edu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */
#include <errno.h>
#include <string.h>
#include <inttypes.h>

#include "list.h"
#include "tgtd.h"
#include "driver.h"

extern struct tgt_driver ibmvio, iscsi, xen, fc;

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
#ifdef FC
	&fc,
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
