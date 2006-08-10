#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "log.h"

int chrdev_open(char *modname, char *devpath, uint8_t minor, int *fd)
{
	FILE *fp;
	char name[256], buf[256];
	int err, major;

	fp = fopen("/proc/devices", "r");
	if (!fp) {
		eprintf("Cannot open control path to the driver\n");
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
	err = mknod(devpath, (S_IFCHR | 0600), (major << 8) | minor);
	if (err) {
		eprintf("cannot create %s %s\n", devpath, strerror(errno));
		return -errno;
	}

	*fd = open(devpath, O_RDWR);
	if (*fd < 0) {
		eprintf("cannot open %s %s\n", devpath, strerror(errno));
		return -errno;
	}

	return 0;
}
