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

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

int dl_init(struct driver_info *dinfo)
{
	int i, fd, err;
	char path[PATH_MAX];
	mode_t fmode = S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH;
	mode_t dmode = S_IRUSR|S_IWUSR|S_IXUSR|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH;

	system("rm -rf " TGT_LLD_SYSFSDIR);
	err = mkdir(TGT_LLD_SYSFSDIR, dmode);
	if (err < 0) {
		perror("Cannot create " TGT_LLD_SYSFSDIR);
		return err;
	}

	for (i = 0; i < ARRAY_SIZE(dlinfo); i++) {
		snprintf(path, sizeof(path), "%s.so", dlinfo[i].name);
		dlinfo[i].dl = dlopen(path, RTLD_LAZY);
		if (dlinfo[i].dl)
			eprintf("%s library was loaded.\n", dlinfo[i].name);
		else
			eprintf("%s library is not loaded.\n", dlinfo[i].name);

		snprintf(path, sizeof(path), TGT_LLD_SYSFSDIR "/%d-%s",
			 i, dlinfo[i].name);

		fd = open(path, O_RDWR|O_CREAT|O_EXCL, fmode);
		if (fd < 0) {
			eprintf("Cannot create %s.\n", path);
			exit(-1);
		}
	}

	return ARRAY_SIZE(dlinfo);
}

void *dl_poll_init_fn(struct driver_info *dinfo, int idx)
{
	if (dinfo[idx].dl)
		return dlsym(dinfo[idx].dl, "poll_init");
	return NULL;
}

void *dl_poll_fn(struct driver_info *dinfo, int idx)
{
	if (dinfo[idx].dl)
		return dlsym(dinfo[idx].dl, "poll_event");
	return NULL;
}

void *dl_ipc_fn(struct driver_info *dinfo, int typeid)
{
	if (dinfo[typeid].dl)
		return dlsym(dinfo[typeid].dl, "ipc_mgmt");

	return NULL;
}

void *dl_event_fn(struct driver_info *dinfo, int tid, int typeid)
{
	if (dinfo[typeid].dl)
		return dlsym(dinfo[typeid].dl, "async_event");

	return NULL;
}
