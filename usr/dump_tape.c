/*
 *	Dump headers of 'tape' datafile
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
#include <string.h>
#include <inttypes.h>
#include <time.h>
#include "scsi.h"
#include "media.h"
#include "ssc.h"
#include "bs_ssc.h"
#include "libssc.h"

void print_current_header(struct blk_header *pos)
{
	if (pos->a != 'A')
		printf("head sanity check failed\n");
	if (pos->z != 'Z')
		printf("tail sanity check failed\n");

	switch (pos->blk_type) {
	case BLK_UNCOMPRESS_DATA:
		printf(" Uncompressed data");
		break;
	case BLK_FILEMARK:
		printf("         Filemark");
		break;
	case BLK_BOT:
		printf("Beginning of Tape");
		break;
	case BLK_EOD:
		printf("      End of Data");
		break;
	case BLK_NOOP:
		printf("      No Operation");
		break;
	default:
		printf("      Unknown type");
		break;
	}
	if (pos->blk_type == BLK_BOT)
		printf("(%d): Capacity %d MB, Blk No.: %" PRId64
		", prev %" PRId64 ", curr %" PRId64 ", next %" PRId64 "\n",
			pos->blk_type,
			pos->blk_sz,
			pos->blk_num,
			(uint64_t)pos->prev,
			(uint64_t)pos->curr,
			(uint64_t)pos->next);
	else
		printf("(%d): Blk No. %" PRId64 ", prev %" PRId64 ""
			", curr %" PRId64 ",  next %" PRId64 ", sz %d\n",
			pos->blk_type,
			pos->blk_num,
			(uint64_t)pos->prev,
			(uint64_t)pos->curr,
			(uint64_t)pos->next,
			pos->ondisk_sz);
}

int skip_to_next_header(int fd, struct blk_header *pos)
{
	int ret;

	ret = ssc_read_blkhdr(fd, pos, pos->next);
	if (ret)
		printf("Could not read complete blk header - short read!!\n");

	return ret;
}

int main(int argc, char *argv[])
{
	int ofp;
	char *progname;
	char datafile[1024] = "";
	loff_t	nread;
	struct MAM_info mam;
	struct blk_header current_position;
	time_t t;
	int a;
	unsigned char *p;

	progname = argv[0];

	if (argc < 2) {
		printf("Usage: %s -f <media>\n", progname);
		exit(1);
	}

	while (argc > 0) {
		if (argv[0][0] == '-') {
			switch (argv[0][1]) {
			case 'f':
				if (argc > 1) {
					strncpy(datafile, argv[1],
							sizeof(datafile));
				} else {
					puts("    More args needed for -f\n");
					exit(1);
				}
				break;
			}
		}
		argv++;
		argc--;
	}

	if (strlen(datafile) == 0) {
		printf("Usage: %s -f <media>\n", progname);
		exit(1);
	}

	ofp = open(datafile, O_RDWR|O_LARGEFILE);
	if (ofp == -1) {
		fprintf(stderr, "%s, ", datafile);
		perror("Could not open");
		exit(1);
	}

	nread = ssc_read_blkhdr(ofp, &current_position, 0);
	if (nread) {
		perror("Could not read blk header");
		exit(1);
	}

	nread = ssc_read_mam_info(ofp, &mam);
	if (nread) {
		perror("Could not read MAM");
		exit(1);
	}
	if (mam.tape_fmt_version != TGT_TAPE_VERSION) {
		printf("Unknown media format version %x\n",
		       mam.tape_fmt_version);
		exit(1);
	}

	printf("Media     : %s\n", mam.barcode);
	switch (mam.medium_type) {
	case CART_UNSPECIFIED:
		printf(" type     : Unspecified\n");
		break;
	case CART_DATA:
		printf(" type     : Data\n");
		break;
	case CART_CLEAN:
		printf(" type     : Cleaning\n");
		break;
	case CART_DIAGNOSTICS:
		printf(" type     : Diagnostics\n");
		break;
	case CART_WORM:
		printf(" type     : WORM\n");
		break;
	case CART_MICROCODE:
		printf(" type     : Microcode\n");
		break;
	default:
		printf(" type     : Unknown\n");
	}
	printf("Media serial number : %s, ", mam.medium_serial_number);

	for (a = strlen((const char *)mam.medium_serial_number); a > 0; a--)
		if (mam.medium_serial_number[a] == '_')
			break;
	if (a) {
		a++;
		p = &mam.medium_serial_number[a];
		t = atoll((const char *)p);
		printf("created %s", ctime(&t));
	}
	printf("\n");

	print_current_header(&current_position);
	while (current_position.blk_type != BLK_EOD) {
		nread = skip_to_next_header(ofp, &current_position);
		if (nread)
			break;
		print_current_header(&current_position);
	}

	return (0);
}
