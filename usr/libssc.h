#ifndef __LIBSSC_H
#define __LIBSSC_H

extern int ssc_read_mam_info(int fd, struct MAM_info *i);
extern int ssc_write_mam_info(int fd, struct MAM_info *i);

#endif
