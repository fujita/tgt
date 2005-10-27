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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/poll.h>

#include "log.h"
#include "dl.h"

#define	MAX_DL_HANDLES	32

struct driver_info {
	char *name;
	void *dl;
	void *pdl;
};

static struct driver_info dinfo[MAX_DL_HANDLES];

static int driver_find_by_name(char *name)
{
	int i;

	for (i = 0; i < MAX_DL_HANDLES; i++)
		if (!strncmp(dinfo[i].name, name, strlen(dinfo[i].name)))
			return i;

	return -ENOENT;
}

int dl_init(char *p)
{
	int i;
	char path[PATH_MAX], *driver, *proto;

	for (i = 0; (driver = strsep(&p, ",")); i++) {
		proto = strchr(driver, ':');
		if (!proto)
			continue;

		*proto++ = '\0';
		dprintf("%s %s\n", driver, proto);

		memset(path, 0, sizeof(path));
		strcpy(path, driver);
		strcat(path, ".so");

		dinfo[i].name = strdup(driver);
		dinfo[i].dl = dlopen(path, RTLD_LAZY);
		if (!dinfo[i].dl)
			fprintf(stderr, "%s\n", dlerror());
	}

	return i;
}

void dl_config_load(void)
{
	void (* fn)(void);
	int i;

	for (i = 0; i < MAX_DL_HANDLES; i++) {
		if (!dinfo[i].dl)
			continue;

		fn = dlsym(dinfo[i].dl, "initial_config_load");
		if (!fn)
			eprintf("%s\n", dlerror());
		else
			fn();
	}
}

void *dl_poll_init_fn(int idx)
{
	if (dinfo[idx].dl)
		return dlsym(dinfo[idx].dl, "poll_init");
	return NULL;
}

void *dl_poll_fn(int idx)
{
	if (dinfo[idx].dl)
		return dlsym(dinfo[idx].dl, "poll_event");
	return NULL;
}

void *dl_ipc_fn(char *name)
{
	int idx = driver_find_by_name(name);
	if (idx < 0)
		eprintf("%d %s\n", idx, name);

	if (idx >= 0 && dinfo[idx].dl)
		return dlsym(dinfo[idx].dl, "ipc_mgmt");
	return NULL;
}

void *dl_event_fn(int tid)
{
	char path[PATH_MAX], name[PATH_MAX];
	int idx, fd, err;

	memset(path, 0, sizeof(path));

	sprintf(path, "/sys/class/tgt_target/target%d/name", tid);
	fd = open(path, O_RDONLY);
	if (fd < 0)
		return NULL;

	err = read(fd, name, sizeof(name));
	close(fd);
	if (err < 0)
		return NULL;

	idx = driver_find_by_name(name);
	if (idx < 0)
		eprintf("%d %s %d\n", idx, name, tid);

	if (idx >= 0 && dinfo[idx].dl)
		return dlsym(dinfo[idx].dl, "async_event");

	return NULL;
}
