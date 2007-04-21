/*
 * iSCSI transport functions
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
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>

#include "iscsid.h"
#include "transport.h"

struct iscsi_transport *iscsi_transports[] = {
	&iscsi_tcp,
	NULL,
};

int lld_index;

int iscsi_init(int index)
{
	int i, err, nr = 0;

	lld_index = index;

	for (i = 0; iscsi_transports[i]; i++) {
		err = iscsi_transports[i]->ep_init();
		if (!err)
			nr++;
	}

	return !nr;
}
