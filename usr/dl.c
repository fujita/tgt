/*
 * SCSI target dynamic library
 *
 * Copyright (C) 2005 FUJITA Tomonori <tomof@acm.org>
 * Copyright (C) 2005 Mike Christie <michaelc@cs.wisc.edu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */
#include <string.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/poll.h>

#include "log.h"
#include "dl.h"
#include "util.h"
#include "tgt_sysfs.h"

/*
 * Software LLDs needs to set up a target (that means tgtd must load
 * thier libraries) before a scsi_host is created in kernel space. In
 * short, tgtd needs to load LLD libraries before it knows what
 * libraries are avilable (through sysfs). I chose the easiest way.
 */

struct driver_info dlinfo[] = {
	{"istgt", }, {"ibmvstgt",},
};

/* Bah, any better way? */
static char *dl_fn_table[] = {
	"poll_init",
	"poll_event",
	"ipc_mgmt",
	"scsi_inquiry",
	"scsi_report_luns",
	"scsi_lun_to_int",
};

int dl_init(struct driver_info *dinfo)
{
	int i, j, fd, err;
	char path[PATH_MAX];

	system("rm -rf " TGT_LLD_SYSFSDIR);
	err = mkdir(TGT_LLD_SYSFSDIR, DEFDMODE);
	if (err < 0) {
		perror("Cannot create " TGT_LLD_SYSFSDIR);
		return err;
	}

	for (i = 0; i < ARRAY_SIZE(dlinfo); i++) {
		snprintf(path, sizeof(path), "lib%s.so", dlinfo[i].name);
		dlinfo[i].dl = dlopen(path, RTLD_LAZY);
		if (dlinfo[i].dl) {
			eprintf("%s library was loaded.\n", dlinfo[i].name);
			for (j = 0; j < ARRAY_SIZE(dl_fn_table); j++)
				dlinfo[i].fn[j] =
					dlsym(dlinfo[i].dl, dl_fn_table[j]);
		} else
			eprintf("%s library is not loaded.\n", dlinfo[i].name);

		snprintf(path, sizeof(path), TGT_LLD_SYSFSDIR "/%d-%s",
			 i, dlinfo[i].name);

		fd = open(path, O_RDWR|O_CREAT|O_EXCL, DEFFMODE);
		if (fd < 0) {
			eprintf("Cannot create %s.\n", path);
			exit(1);
		}
	}

	return ARRAY_SIZE(dlinfo);
}

void *dl_fn(struct driver_info *dinfo, int idx, int function)
{
	return dinfo[idx].fn[function];
}
