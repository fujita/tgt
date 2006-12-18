/*
 * xenbus.c
 *
 * xenbus interface to the blocktap.
 *
 * this handles the top-half of integration with block devices through the
 * store -- the tap driver negotiates the device channel etc, while the
 * userland tap client needs to sort out the disk parameters etc.
 *
 * (c) 2005 Andrew Warfield and Julian Chesterfield
 *
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation; or, when distributed
 * separately from the Linux kernel or incorporated into other
 * software packages, subject to the following license:
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this source file (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <printf.h>
#include <string.h>
#include <err.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <xs.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>
#include <sys/time.h>

/* FIXME */
#define SRP_RING_PAGES 1
#define SRP_MAPPED_PAGES 88

#include "list.h"
#include "util.h"
#include "tgtd.h"
#include "xs_api.h"

struct backend_info
{
	int frontend_id;

	char *path;
	char *backpath;
	char *frontpath;

	struct list_head list;
};

static LIST_HEAD(belist);

static int strsep_len(const char *str, char c, unsigned int len)
{
	unsigned int i;

	for (i = 0; str[i]; i++)
		if (str[i] == c) {
			if (len == 0)
				return i;
			len--;
		}
	return (len == 0) ? i : -ERANGE;
}

static int get_be_id(const char *str)
{
	int len,end;
	const char *ptr;
	char *tptr, num[10];

	len = strsep_len(str, '/', 6);
	end = strlen(str);
	if((len < 0) || (end < 0)) return -1;

	ptr = str + len + 1;
	strncpy(num,ptr,end - len);
	tptr = num + (end - (len + 1));
	*tptr = '\0';

	return atoi(num);
}

static struct backend_info *be_lookup_be(const char *bepath)
{
	struct backend_info *be;

	list_for_each_entry(be, &belist, list)
		if (strcmp(bepath, be->backpath) == 0)
			return be;
	return (struct backend_info *)NULL;
}

static int be_exists_be(const char *bepath)
{
	return (be_lookup_be(bepath) != NULL);
}

static struct backend_info *be_lookup_fe(const char *fepath)
{
	struct backend_info *be;

	list_for_each_entry(be, &belist, list)
		if (strcmp(fepath, be->frontpath) == 0)
			return be;
	return (struct backend_info *)NULL;
}

#if 0
static int backend_remove(struct xs_handle *h, struct backend_info *be)
{
	/* Unhook from be list. */
	list_del(&be->list);
	dprintf("Removing backend\n");

	/* Free everything else. */
	if (be->blkif) {
		dprintf("Freeing blkif dev [%d]\n",be->blkif->devnum);
		free_blkif(be->blkif);
	}
	if (be->frontpath)
		free(be->frontpath);
	if (be->backpath)
		free(be->backpath);
	free(be);
	return 0;
}
#endif

static int tgt_device_setup(struct xs_handle *h, char *bepath)
{
	struct backend_info *be;
	char *path = NULL, *p, *dev;
	int len, err = -EINVAL;
	long int handle;
	uint64_t lun;

	be = be_lookup_be(bepath);
	if (!be) {
		dprintf("ERROR: backend changed called for nonexistent "
			"backend! (%s)\n", bepath);
		return err;
	}

        err = xs_gather(h, bepath, "dev", NULL, &path, NULL);
        if (err) {
                eprintf("cannot get dev %d\n", err);
		return err;
	}

	/* TODO: we need to lun param. */
	lun = 0;

	err = tgt_device_create(be->frontend_id, lun);
	{
		char line[1024];
		int len;

		memset(line, 0, sizeof(line));
		len = snprintf(line, sizeof(line), "path");
		len += 1;
		snprintf(line + len, sizeof(line) - len, "%s", path);
		err = tgt_device_update(be->frontend_id, lun, line);
	}

	dprintf("%d path %s\n", err, path);
	if (err)
		return err;

	err = xs_printf(h, be->backpath, "info", "%d", be->frontend_id);
	if (!err)
		dprintf("ERROR: Failed writing info");

	dprintf("[SETUP] Complete\n\n");

	return err;
}

static int xen_chrdev_open(char *name, uint8_t minor)
{
	FILE *f;
	char devname[256];
	char buf[256];
	int devn;
	int ctlfd;

	f = fopen("/proc/devices", "r");
	if (!f) {
		eprintf("Cannot open control path to the driver\n");
		return -1;
	}

	devn = 0;
	while (!feof(f)) {
		if (!fgets(buf, sizeof (buf), f))
			break;

		if (sscanf(buf, "%d %s", &devn, devname) != 2)
			continue;

		if (!strcmp(devname, name))
			break;

		devn = 0;
	}

	fclose(f);
	if (!devn) {
		eprintf("cannot find %s in /proc/devices - "
			"make sure the module is loaded\n", name);
		return -1;
	}

	snprintf(devname, sizeof(devname), "/dev/%s%d", name, minor);

	unlink(devname);
	if (mknod(devname, (S_IFCHR | 0600), (devn << 8) | minor)) {
		eprintf("cannot create %s %s\n", devname, strerror(errno));
		return -1;
	}

	ctlfd = open(devname, O_RDWR);
	if (ctlfd < 0) {
		eprintf("cannot open %s %s\n", devname, strerror(errno));
		return -1;
	}

	return ctlfd;
}

/*
 * Xenstore watch callback entry point. This code replaces the hotplug scripts,
 * and as soon as the xenstore backend driver entries are created, this script
 * gets called.
 */
static void tgt_probe(struct xs_handle *h, struct xenbus_watch *w,
		      const char *bepath_im)
{
	struct backend_info *be = NULL;
	char *frontend = NULL, *bepath = NULL, *p;
	int err, len, fd, msize = (SRP_RING_PAGES + SRP_MAPPED_PAGES) * PAGE_SIZE;
	void *addr;
	uint32_t hostno;
	char targetname[16];

	bepath = strdup(bepath_im);
	if (!bepath) {
		dprintf("No path\n");
		return;
	}

	/*
	 *asserts that xenstore structure is always 7 levels deep
	 *e.g. /local/domain/0/backend/vbd/1/2049
	 */
        len = strsep_len(bepath, '/', 7);
        if (len < 0)
		goto free_be;
        bepath[len] = '\0';

	be = calloc(1, sizeof(*be));
	if (!be) {
		dprintf("ERROR: allocating backend structure\n");
		goto free_be;
	}

	err = xs_gather(h, bepath,
			"frontend-id", "%d", &be->frontend_id,
			"frontend", NULL, &frontend,
			NULL);

	dprintf("%d %d %s\n", err, be->frontend_id, frontend);
	if (err) {
		/*
		 *Unable to find frontend entries,
		 *bus-id is no longer valid
		 */
		dprintf("ERROR: Frontend-id check failed, removing backend: [%s]\n",bepath);

		/*BE info should already exist, free new mem and find old entry*/
		free(be);
		be = be_lookup_be(bepath);
/* 		if (be && be->blkif) */
/* 			backend_remove(h, be); */
/* 		else */
/* 			goto free_be; */
	        if (bepath)
			free(bepath);
		return;
	}

        /* Are we already tracking this device? */
        if (be_exists_be(bepath))
		goto free_be;

        err = xs_gather(h, bepath, "hostno", "%u", &hostno, NULL);
	if (err)
		goto free_be;

	fd = xen_chrdev_open("scsiback", hostno);
	if (fd < 0)
		goto free_be;

	addr = mmap(NULL, msize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (addr == MAP_FAILED) {
		eprintf("failed to mmap %u %s\n", msize, strerror(errno));
		goto close_fd;
	}
	dprintf("addr: %p size: %d\n", addr, msize);

	snprintf(targetname, sizeof(targetname), "xen %d", be->frontend_id);
	err = tgt_target_create(0, be->frontend_id, targetname);
	if (err && err != -EEXIST)
		goto close_fd;

	be->backpath = bepath;
       	be->frontpath = frontend;

	/* FIXME */
	err = tgt_target_bind(be->frontend_id, hostno, 0);

        list_add(&be->list, &belist);

        dprintf("[PROBE]\tADDED NEW DEVICE (%s)\n", bepath);
	dprintf("\tFRONTEND (%s),(%d)\n", frontend, be->frontend_id);

	tgt_device_setup(h, bepath);
	return;

close_fd:
	close(fd);
free_be:
	if (frontend)
		free(frontend);
        if (bepath)
		free(bepath);
	if(be)
		free(be);
	return;
}

/*
 *We set a general watch on the backend vbd directory
 *ueblktap_probe is called for every update
 *Our job is simply to monitor for new entries, and to
 *create the state and attach a disk.
 */

int add_blockdevice_probe_watch(struct xs_handle *h, const char *domname)
{
	char *domid, *path;
	struct xenbus_watch *watch;
	int er;

	domid = get_dom_domid(h, domname);

	dprintf("%s: %s\n", domname, (domid != NULL) ? domid : "[ not found! ]");

	asprintf(&path, "/local/domain/%s/backend/scsi", domid);
	if (path == NULL)
		return -ENOMEM;

	watch = (struct xenbus_watch *)malloc(sizeof(struct xenbus_watch));
	if (!watch) {
		dprintf("ERROR: unable to malloc vbd_watch [%s]\n", path);
		return -EINVAL;
	}
	watch->node = path;
	watch->callback = tgt_probe;
	er = register_xenbus_watch(h, watch);
	if (er == 0) {
		dprintf("ERROR: adding vbd probe watch %s\n", path);
		return -EINVAL;
	}
	return 0;
}
