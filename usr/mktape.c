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

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <syslog.h>
#include <string.h>
#include <time.h>
#include <inttypes.h>
#include "media.h"
#include "bs_ssc.h"
#include "ssc.h"
#include "libssc.h"

const char *mktape_version = "0.01";

void usage(char *progname)
{

	printf("Usage: %s -m barcode -s size -t type\n", progname);
	printf("       Where 'size' is in Megabytes\n");
	printf("             'type' is data | clean | WORM\n");
	printf("             'barcode' is a string of chars\n\n");
}

int main(int argc, char *argv[])
{
	int file;
	struct blk_header h;
	struct MAM_info mi;
	uint8_t current_media[1024];
	char *progname = argv[0];
	char *barcode = NULL;
	char *media_type = NULL;
	char *media_capacity = NULL;
	uint32_t size;
	int ret;

	if (argc < 2) {
		usage(progname);
		exit(1);
	}

	while (argc > 0) {
		if (argv[0][0] == '-') {
			switch (argv[0][1]) {
			case 'm':
				if (argc > 1) {
					barcode = argv[1];
				} else {
					puts("    More args needed for -m\n");
					exit(1);
				}
				break;
			case 's':
				if (argc > 1) {
					media_capacity = argv[1];
				} else {
					puts("    More args needed for -s\n");
					exit(1);
				}
				break;
			case 't':
				if (argc > 1) {
					media_type = argv[1];
				} else {
					puts("    More args needed for -t\n");
					exit(1);
				}
				break;
			case 'V':
				printf("%s: version %s\n",
						progname, mktape_version);
				break;
			}
		}
		argv++;
		argc--;
	}

	if (barcode == NULL) {
		usage(progname);
		exit(1);
	}
	if (media_capacity == NULL) {
		usage(progname);
		exit(1);
	}
	if (media_type == NULL) {
		usage(progname);
		exit(1);
	}

	sscanf(media_capacity, "%d", &size);
	if (size == 0)
		size = 8000;

	h.a = 'A';
	h.z = 'Z';
	h.blk_type = BLK_BOT;
	h.blk_num = 0;
	h.blk_sz = size;
	h.prev = 0;
	h.curr = 0;
	h.next = sizeof(struct MAM) + sizeof(h);

	printf("blk_sz: %d, next %" PRId64 ", %" PRId64 "\n",
				h.blk_sz, h.next, h.next);
	printf("Sizeof(mam): %" PRId64 ", sizeof(h): %" PRId64 "\n",
	       (uint64_t)sizeof(struct MAM), (uint64_t)sizeof(h));

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
	} else if (!strncmp("WORM", media_type, 4)) {
		mi.medium_type = CART_WORM;
	} else {
		mi.medium_type = CART_DATA;
	}

	sprintf((char *)mi.medium_serial_number, "%s_%d", barcode,
		(int)time(NULL));
	sprintf((char *)mi.barcode, "%-31s", barcode);
	sprintf((char *)current_media, "%s", barcode);

	syslog(LOG_DAEMON|LOG_INFO, "%s being created", current_media);

	file = creat((char *)current_media, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP);
	if (file == -1) {
		perror("Failed creating file");
		exit(2);
	}

	ret = ssc_write_blkhdr(file, &h, 0);
	if (ret) {
		perror("Unable to write header");
		exit(1);
	}

	ret = ssc_write_mam_info(file, &mi);
	if (ret) {
		perror("Unable to write MAM");
		exit(1);
	}
	memset(&h, 0, sizeof(h));
	h.a = 'A';
	h.z = 'Z';
	h.blk_type = BLK_EOD;
	h.blk_num = 1;
	h.prev = 0;
	h.next = lseek64(file, 0, SEEK_CUR);
	h.curr = h.next;

	ret = ssc_write_blkhdr(file, &h, h.next);
	if (ret) {
		perror("Unable to write header");
		exit(1);
	}
	close(file);

exit(0);
}

