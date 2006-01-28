/*
 * Dynamic library
 *
 * (C) 2005 FUJITA Tomonori <tomof@acm.org>
 * (C) 2005 Mike Christie <michaelc@cs.wisc.edu>
 *
 * This code is licenced under the GPL.
 */

/* TODO : better handling of dynamic library. */

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

struct driver_info dlinfo[MAX_DL_HANDLES];

char *typeid_to_name(struct driver_info *dinfo, int typeid)
{
	return dinfo[typeid].name;
}

static char *dlname(char *d_name, char *entry)
{
	int fd, err;
	char *p, path[PATH_MAX], buf[PATH_MAX];

	snprintf(path, sizeof(path),
		 TGT_TYPE_SYSFSDIR "/%s/%s", d_name, entry);
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		eprintf("%s\n", path);
		return NULL;
	}
	memset(buf, 0, sizeof(buf));
	err = read(fd, buf, sizeof(buf));
	close(fd);
	if (err < 0) {
		eprintf("%s %d\n", path, errno);
		return NULL;
	}

	p = strchr(buf, '\n');
	if (p)
		*p = '\0';

	return strdup(buf);
}

static int filter(const struct dirent *dir)
{
	return strcmp(dir->d_name, ".") && strcmp(dir->d_name, "..");
}

int dl_init(struct driver_info *dinfo)
{
	int i, nr, idx;
	char path[PATH_MAX], *p;
	struct dirent **namelist;
	struct driver_info *di;

	nr = scandir(TGT_TYPE_SYSFSDIR, &namelist, filter, alphasort);
	for (i = 0; i < nr; i++) {
		for (p = namelist[i]->d_name; !isdigit((int) *p); p++)
			;
		idx = atoi(p);
		if (idx > MAX_DL_HANDLES) {
			eprintf("Too large dl idx %s %d\n",
				namelist[i]->d_name, idx);
			continue;
		}
		di = &dinfo[idx];

		di->name = dlname(namelist[i]->d_name, "name");
		if (!di->name)
			continue;

		snprintf(path, sizeof(path), "%s.so", di->name);
		di->dl = dlopen(path, RTLD_LAZY);
		if (!di->dl)
			eprintf("%s %s\n", path, dlerror());

		di->proto = dlname(namelist[i]->d_name, "protocol");
		if (!di->proto)
			continue;

		snprintf(path, sizeof(path), "%s.so", di->proto);
		di->pdl = dlopen(path, RTLD_LAZY);
		if (!di->pdl)
			eprintf("%s %s\n", path, dlerror());
	}

	for (i = 0; i < nr; i++)
		free(namelist[i]);
	free(namelist);

	return 0;
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

void *dl_proto_cmd_process(struct driver_info *dinfo, int tid, int typeid)
{
	if (dinfo[typeid].pdl)
		return dlsym(dinfo[typeid].pdl, "cmd_process");

	return NULL;
}

void *dl_proto_get_devid(struct driver_info *dinfo, int tid, int typeid)
{
	if (dinfo[typeid].pdl)
		return dlsym(dinfo[typeid].pdl, "get_devid");

	return NULL;
}

void *dl_event_fn(struct driver_info *dinfo, int tid, int typeid)
{
	if (dinfo[typeid].dl)
		return dlsym(dinfo[typeid].dl, "async_event");

	return NULL;
}

void *dl_cmd_done_fn(struct driver_info *dinfo, int typeid)
{
	if (dinfo[typeid].pdl)
		return dlsym(dinfo[typeid].pdl, "cmd_done");

	return NULL;
}
