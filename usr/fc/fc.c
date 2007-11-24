/*
 * SCSI command processing specific to fibre channel drivers
 *
 * Copyright (C) 2007 FUJITA Tomonori <tomof@acm.org>
 * Copyright (C) 2007 Mike Christie <michaelc@cs.wisc.edu>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA
 */
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <syscall.h>
#include <unistd.h>
#include <linux/fs.h>
#include <scsi/scsi.h>
#include <sys/mman.h>

#include "list.h"
#include "util.h"
#include "tgtd.h"
#include "target.h"
#include "driver.h"
#include "spc.h"
#include "scsi.h"

static struct tgt_driver fc = {
	.name			= "fc",
	.use_kernel		= 1,
	.cmd_end_notify		= kspace_send_cmd_res,
	.mgmt_end_notify	= kspace_send_tsk_mgmt_res,
	.default_bst		= "mmap",
};

__attribute__((constructor)) static void fc_driver_constructor(void)
{
	register_driver(&fc);
}
