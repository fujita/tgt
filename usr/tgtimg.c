/*
 *	Create blank media files for bs_tape backing store
 *
 * Copyright (C) 2008 Mark Harvey markh794@gmail.com
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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "media.h"
#include "bs_ssc.h"
#include "ssc.h"
#include "libssc.h"
#include "scsi.h"

#undef eprintf
#define eprintf(fmt, args...)						\
do {									\
	fprintf(stderr, "%s: " fmt, program_name, ##args);		\
} while (0)

#undef dprintf
#define dprintf(fmt, args...)						\
do {									\
	if (debug)							\
		fprintf(stderr, "%s %d: " fmt,				\
			__FUNCTION__, __LINE__, ##args);		\
} while (0)

enum {
	OP_NEW,
	OP_SHOW,
};

static char program_name[] = "tgtimg";

static char *short_options = "ho:Y:b:s:t:f:";

struct option const long_options[] = {
	{"help", no_argument, NULL, 'h'},
	{"op", required_argument, NULL, 'o'},
	{"device-type", required_argument, NULL, 'Y'},
	{"barcode", required_argument, NULL, 'b'},
	{"size", required_argument, NULL, 's'},
	{"type", required_argument, NULL, 't'},
	{"file", required_argument, NULL, 'f'},
	{NULL, 0, NULL, 0},
};

static void usage(int status)
{
	if (status != 0)
		fprintf(stderr, "Try `%s --help' for more information.\n", program_name);
	else {
		printf("Usage: %s [OPTION]\n", program_name);
		printf("\
Linux SCSI Target Framework Image File Utility, version %s\n\
\n\
  --op new --device-type tape --barcode=[code] --size=[size] --type=[type] --file=[path]\n\
                         create a new tape image file.\n\
                         [code] is a string of chars.\n\
                         [size] is media size (in megabytes).\n\
                         [type] is media type (data, clean or WORM)\n\
                         [path] is a newly created file\n\
  --help                 display this help and exit\n\
\n\
Report bugs to <stgt@vger.kernel.org>.\n", TGT_VERSION);
	}
	exit(status == 0 ? 0 : EINVAL);
}

static int str_to_device_type(char *str)
{
	if (!strcmp(str, "tape"))
		return TYPE_TAPE;
	else {
		eprintf("unknown target type: %s\n", str);
		exit(EINVAL);
	}
}

static int str_to_op(char *str)
{
	if (!strcmp("new", str))
		return OP_NEW;
	else if (!strcmp("show", str))
		return OP_SHOW;
	else {
		eprintf("unknown operation: %s\n", str);
		exit(1);
	}
}

static int ssc_new(int op, char *path, char *barcode, char *capacity,
		   char *media_type)
{
	struct blk_header_info hdr, *h = &hdr;
	struct MAM_info mi;
	int fd, ret;
	uint8_t current_media[1024];
	uint32_t size;

	sscanf(capacity, "%d", &size);
	if (size == 0)
		size = 8000;

	memset(h, 0, sizeof(h));
	h->blk_type = BLK_BOT;
	h->blk_num = 0;
	h->blk_sz = size;
	h->prev = 0;
	h->curr = 0;
	h->next = sizeof(struct MAM) + SSC_BLK_HDR_SIZE;

	printf("blk_sz: %d, next %" PRId64 ", %" PRId64 "\n",
				h->blk_sz, h->next, h->next);
	printf("Sizeof(mam): %" PRId64 ", sizeof(h): %" PRId64 "\n",
	       (uint64_t)sizeof(struct MAM), (uint64_t)SSC_BLK_HDR_SIZE);

	memset(&mi, 0, sizeof(mi));

	mi.tape_fmt_version = TGT_TAPE_VERSION;
	mi.max_capacity = size * 1048576;
	mi.remaining_capacity = size * 1048576;
	mi.MAM_space_remaining = sizeof(mi.vendor_unique);
	mi.medium_length = 384;	/* 384 tracks */
	mi.medium_width = 127;		/* 127 x tenths of mm (12.7 mm) */
	memcpy(mi.medium_manufacturer, "Foo     ", 8);
	memcpy(mi.application_vendor, "Bar     ", 8);

	if (!strncmp("clean", media_type, 5)) {
		mi.medium_type = CART_CLEAN;
		mi.medium_type_information = 20; /* Max cleaning loads */
	} else if (!strncmp("WORM", media_type, 4))
		mi.medium_type = CART_WORM;
	else
		mi.medium_type = CART_DATA;

	sprintf((char *)mi.medium_serial_number, "%s_%d", barcode,
		(int)time(NULL));
	sprintf((char *)mi.barcode, "%-31s", barcode);
	sprintf((char *)current_media, "%s", barcode);

	syslog(LOG_DAEMON|LOG_INFO, "%s being created", path);

	fd = creat(path, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP);
	if (fd < 0) {
		perror("Failed creating file");
		exit(2);
	}

	ret = ssc_write_blkhdr(fd, h, 0);
	if (ret) {
		perror("Unable to write header");
		exit(1);
	}

	ret = ssc_write_mam_info(fd, &mi);
	if (ret) {
		perror("Unable to write MAM");
		exit(1);
	}

	memset(h, 0, sizeof(h));
	h->blk_type = BLK_EOD;
	h->blk_num = 1;
	h->prev = 0;
	h->next = lseek64(fd, 0, SEEK_CUR);
	h->curr = h->next;

	ret = ssc_write_blkhdr(fd, h, h->next);
	if (ret) {
		perror("Unable to write header");
		exit(1);
	}
	close(fd);

	return 0;
}

static int ssc_ops(int op, char *path, char *barcode, char *capacity,
		   char *media_type)
{
	if (op == OP_NEW)
		return ssc_new(op, path, barcode, capacity, media_type);
	else {
		eprintf("unknown the operation type\n");
		usage(1);
	}

	return 0;
}

int main(int argc, char **argv)
{
	int ch, longindex;
	char *barcode = NULL;
	char *media_type = NULL;
	char *media_capacity = NULL;
	int dev_type = TYPE_TAPE;
	int op = -1;
	char *path = NULL;

	while ((ch = getopt_long(argc, argv, short_options,
				 long_options, &longindex)) >= 0) {
		switch (ch) {
		case 'o':
			op = str_to_op(optarg);
			break;
		case 'Y':
			dev_type = str_to_device_type(optarg);
			break;
		case 'b':
			barcode = optarg;
			break;
		case 's':
			media_capacity = optarg;
			break;
		case 't':
			media_type = optarg;
			break;
		case 'f':
			path = optarg;
			break;
		case 'h':
			usage(0);
			break;
		default:
			eprintf("unrecognized option '%s'\n", optarg);
			usage(1);
		}
	}

	if (optind < argc) {
		eprintf("unrecognized option '%s'\n", argv[optind]);
		usage(1);
	}

	if (op < 0) {
		eprintf("specify the operation type\n");
		usage(1);
	}

	if (!path) {
		eprintf("specify a newly created file\n");
		usage(1);
	}

	if (dev_type == TYPE_TAPE)
		ssc_ops(op, path, barcode, media_capacity, media_type);
	else {
		eprintf("unsupported the device type operation\n");
		usage(1);
	}

	return 0;
}
