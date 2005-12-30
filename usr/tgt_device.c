/*
 * target framework Device
 *
 * (C) 2005 FUJITA Tomonori <tomof@acm.org>
 * (C) 2005 Mike Christie <michaelc@cs.wisc.edu>
 * This code is licenced under the GPL.
 */

/*
 * This is just makeshift for removing device stuff in kernel space
 * and should be replaced soon.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <errno.h>
#include <asm/byteorder.h>
#include <asm/page.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <fcntl.h>
#include <linux/fs.h>

#include "tgtd.h"
#include "tgt_sysfs.h"

static mode_t dmode = S_IRUSR|S_IWUSR|S_IXUSR|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH;
static mode_t fmode = S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH;

int tgt_device_create(int tid, uint64_t lun, int dfd)
{
	int err, fd;
	struct stat st;
	char path[PATH_MAX], buf[32];
	uint64_t size;

	err = ioctl(dfd, BLKGETSIZE64, &size);
	if (err < 0) {
		eprintf("Cannot get size %d\n", dfd);
		return err;
	}

	snprintf(path, sizeof(path), TGT_TARGET_SYSFSDIR "/target%d", tid);
	err = stat(path, &st);
	if (err < 0) {
		eprintf("Cannot find target %d\n", tid);
		return err;
	}

	snprintf(path, sizeof(path), TGT_DEVICE_SYSFSDIR "/device%d:%" PRIu64,
		 tid, lun);

	err = mkdir(path, dmode);
	if (err < 0) {
		eprintf("Cannot create %s\n", path);
		return err;
	}

	snprintf(path, sizeof(path), TGT_DEVICE_SYSFSDIR "/device%d:%" PRIu64 "/fd",
		 tid, lun);
	fd = open(path, O_RDWR|O_CREAT|O_EXCL, fmode);
	if (fd < 0) {
		eprintf("Cannot create %s\n", path);
		return err;
	}
	snprintf(buf, sizeof(buf), "%d", dfd);
	err = write(fd, buf, strlen(buf));
	close(fd);
	if (err < 0) {
		eprintf("Cannot write %s\n", path);
		return err;
	}

	snprintf(path, sizeof(path), TGT_DEVICE_SYSFSDIR "/device%d:%" PRIu64 "/size",
		 tid, lun);
	fd = open(path, O_RDWR|O_CREAT|O_EXCL, fmode);
	if (fd < 0) {
		eprintf("Cannot create %s\n", path);
		return err;
	}
	snprintf(buf, sizeof(buf), "%" PRIu64, size);
	err = write(fd, buf, strlen(buf));
	close(fd);
	if (err < 0) {
		eprintf("Cannot write %s\n", path);
		return err;
	}

	return 0;
}

int tgt_device_destroy(int tid, uint64_t lun)
{
	char path[PATH_MAX];
	int err;

	snprintf(path, sizeof(path), TGT_DEVICE_SYSFSDIR "/device%d:%" PRIu64 "/fd",
		 tid, lun);
	err = unlink(path);
	if (err < 0) {
		eprintf("Cannot unlink %s\n", path);
		goto out;
	}

	snprintf(path, sizeof(path), TGT_DEVICE_SYSFSDIR "/device%d:%" PRIu64 "/size",
		 tid, lun);
	err = unlink(path);
	if (err < 0) {
		eprintf("Cannot unlink %s\n", path);
		goto out;
	}

	snprintf(path, sizeof(path), TGT_DEVICE_SYSFSDIR "/device%d:%" PRIu64,
		 tid, lun);
	err = rmdir(path);
	if (err < 0)
		eprintf("Cannot unlink %s\n", path);

out:
	return err;
}

int tgt_device_init(void)
{
	int err;

	rmdir(TGT_DEVICE_SYSFSDIR);
	err = mkdir(TGT_DEVICE_SYSFSDIR, dmode);
	if (err < 0)
		perror("Cannot create");

	return err;
}
