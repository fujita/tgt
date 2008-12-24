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

static char program_name[] = "tgtimg";

static char *short_options = "ho:m:b:s:t:";

struct option const long_options[] = {
	{"help", no_argument, NULL, 'h'},
	{"op", required_argument, NULL, 'o'},
	{"mode", required_argument, NULL, 'm'},
	{"barcode", required_argument, NULL, 'b'},
	{"size", required_argument, NULL, 's'},
	{"type", required_argument, NULL, 't'},
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
  --barcode=[code] --size=[size] --type=[type]\n\
		   create a new tape image file. [code] is a string of chars.\n\
		   [size] is in Megabytes. [type] is data, clean or WORM\n\
  --help           display this help and exit\n\
\n\
Report bugs to <stgt@vger.kernel.org>.\n", TGT_VERSION);
	}
	exit(status == 0 ? 0 : EINVAL);
}

int main(int argc, char **argv)
{
	int ch, longindex;
	int file;
	struct blk_header_info hdr, *h = &hdr;
	struct MAM_info mi;
	uint8_t current_media[1024];
	char *barcode = NULL;
	char *media_type = NULL;
	char *media_capacity = NULL;
	uint32_t size;
	int ret;

	while ((ch = getopt_long(argc, argv, short_options,
				 long_options, &longindex)) >= 0) {
		switch (ch) {
		case 'm':
			barcode = optarg;
			break;
		case 's':
			media_capacity = optarg;
			break;
		case 't':
			media_type = optarg;
			break;
		case 'h':
			usage(0);
			break;
		default:
			usage(1);
		}
	}

	if (barcode == NULL) {
		usage(1);
	}
	if (media_capacity == NULL) {
		usage(1);
	}
	if (media_type == NULL) {
		usage(1);
	}

	sscanf(media_capacity, "%d", &size);
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

	ret = ssc_write_blkhdr(file, h, 0);
	if (ret) {
		perror("Unable to write header");
		exit(1);
	}

	ret = ssc_write_mam_info(file, &mi);
	if (ret) {
		perror("Unable to write MAM");
		exit(1);
	}

	memset(h, 0, sizeof(h));
	h->blk_type = BLK_EOD;
	h->blk_num = 1;
	h->prev = 0;
	h->next = lseek64(file, 0, SEEK_CUR);
	h->curr = h->next;

	ret = ssc_write_blkhdr(file, h, h->next);
	if (ret) {
		perror("Unable to write header");
		exit(1);
	}
	close(file);

exit(0);
}

