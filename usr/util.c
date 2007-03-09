#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <sys/sysmacros.h>

#include "log.h"

int chrdev_open(char *modname, char *devpath, uint8_t minor, int *fd)
{
	FILE *fp;
	char name[256], buf[256];
	int err, major;

	fp = fopen("/proc/devices", "r");
	if (!fp) {
		eprintf("Cannot open /proc/devices, %m\n");
		return -1;
	}

	major = 0;
	while (!feof(fp)) {
		if (!fgets(buf, sizeof (buf), fp))
			break;

		if (sscanf(buf, "%d %s", &major, name) != 2)
			continue;

		if (!strcmp(name, modname))
			break;
		major = 0;
	}
	fclose(fp);

	if (!major) {
		eprintf("cannot find %s in /proc/devices - "
			"make sure the module is loaded\n", modname);
		return -1;
	}

	unlink(devpath);
	err = mknod(devpath, (S_IFCHR | 0600), makedev(major, minor));
	if (err) {
		eprintf("cannot create %s, %m\n", devpath);
		return -errno;
	}

	*fd = open(devpath, O_RDWR);
	if (*fd < 0) {
		eprintf("cannot open %s, %m\n", devpath);
		return -errno;
	}

	return 0;
}

int backed_file_open(char *path, int oflag, uint64_t *size)
{
	int fd, err;
	struct stat64 st;

	fd = open(path, oflag);
	if (fd < 0) {
		eprintf("Could not open %s, %m\n", path);
		return fd;
	}

	err = fstat64(fd, &st);
	if (err < 0) {
		eprintf("Cannot get stat %d, %m\n", fd);
		goto close_fd;
	}

	if (S_ISREG(st.st_mode))
		*size = st.st_size;
	else if(S_ISBLK(st.st_mode)) {
		err = ioctl(fd, BLKGETSIZE64, size);
		if (err < 0) {
			eprintf("Cannot get size, %m\n");
			goto close_fd;
		}
	} else {
		eprintf("Cannot use this mode %x\n", st.st_mode);
		err = -EINVAL;
		goto close_fd;
	}

	return fd;

close_fd:
	close(fd);
	return err;
}

int set_non_blocking(int fd)
{
	int err;

	err = fcntl(fd, F_GETFL);
	if (err < 0) {
		eprintf("unable to get fd flags, %m\n");
	} else {
		err = fcntl(fd, F_SETFL, err | O_NONBLOCK);
		if (err == -1)
			eprintf("unable to set fd flags, %m\n");
		else
			err = 0;
	}
	return err;
}
