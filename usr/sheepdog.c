#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/socket.h>

#include "list.h"
#include "tgtd.h"
#include "util.h"
#include "log.h"
#include "sheepdog.h"

/*
 * 64 bit FNV-1a non-zero initial basis
 */
#define FNV1A_64_INIT ((uint64_t)0xcbf29ce484222325ULL)

/*
 * 64 bit Fowler/Noll/Vo FNV-1a hash code
 */
static inline uint64_t fnv_64a_buf(void *buf, size_t len, uint64_t hval)
{
    unsigned char *bp = buf;
    unsigned char *be = bp + len;
    while (bp < be) {
        hval ^= (uint64_t) *bp++;
        hval += (hval << 1) + (hval << 4) + (hval << 5) +
            (hval << 7) + (hval << 8) + (hval << 40);
    }
    return hval;
}

static inline int is_data_obj_writeable(SheepdogInode *inode, unsigned int idx)
{
    return inode->vdi_id == inode->data_vdi_id[idx];
}

static inline int is_data_obj(uint64_t oid)
{
    return !(VDI_BIT & oid);
}

static inline uint64_t data_oid_to_idx(uint64_t oid)
{
    return oid & (MAX_DATA_OBJS - 1);
}

static inline uint64_t vid_to_vdi_oid(uint32_t vid)
{
    return VDI_BIT | ((uint64_t)vid << VDI_SPACE_SHIFT);
}

static inline uint64_t vid_to_vmstate_oid(uint32_t vid, uint32_t idx)
{
    return VMSTATE_BIT | ((uint64_t)vid << VDI_SPACE_SHIFT) | idx;
}

static inline uint64_t vid_to_data_oid(uint32_t vid, uint32_t idx)
{
    return ((uint64_t)vid << VDI_SPACE_SHIFT) | idx;
}

static const char * sd_strerror(int err)
{
    int i;

    static const struct {
        int err;
        const char *desc;
    } errors[] = {
        {SD_RES_SUCCESS, "Success"},
        {SD_RES_UNKNOWN, "Unknown error"},
        {SD_RES_NO_OBJ, "No object found"},
        {SD_RES_EIO, "I/O error"},
        {SD_RES_VDI_EXIST, "VDI exists already"},
        {SD_RES_INVALID_PARMS, "Invalid parameters"},
        {SD_RES_SYSTEM_ERROR, "System error"},
        {SD_RES_VDI_LOCKED, "VDI is already locked"},
        {SD_RES_NO_VDI, "No vdi found"},
        {SD_RES_NO_BASE_VDI, "No base VDI found"},
        {SD_RES_VDI_READ, "Failed read the requested VDI"},
        {SD_RES_VDI_WRITE, "Failed to write the requested VDI"},
        {SD_RES_BASE_VDI_READ, "Failed to read the base VDI"},
        {SD_RES_BASE_VDI_WRITE, "Failed to write the base VDI"},
        {SD_RES_NO_TAG, "Failed to find the requested tag"},
        {SD_RES_STARTUP, "The system is still booting"},
        {SD_RES_VDI_NOT_LOCKED, "VDI isn't locked"},
        {SD_RES_SHUTDOWN, "The system is shutting down"},
        {SD_RES_NO_MEM, "Out of memory on the server"},
        {SD_RES_FULL_VDI, "We already have the maximum vdis"},
        {SD_RES_VER_MISMATCH, "Protocol version mismatch"},
        {SD_RES_NO_SPACE, "Server has no space for new objects"},
        {SD_RES_WAIT_FOR_FORMAT, "Sheepdog is waiting for a format operation"},
        {SD_RES_WAIT_FOR_JOIN, "Sheepdog is waiting for other nodes joining"},
        {SD_RES_JOIN_FAILED, "Target node had failed to join sheepdog"},
    };

    for (i = 0; i < ARRAY_SIZE(errors); ++i) {
        if (errors[i].err == err) {
            return errors[i].desc;
        }
    }

    return "Invalid error code";
}

/*
 * Send/recv data with iovec buffers
 *
 * This function send/recv data from/to the iovec buffer directly.
 * The first `offset' bytes in the iovec buffer are skipped and next
 * `len' bytes are used.
 *
 * For example,
 *
 *   do_send_recv(sockfd, iov, len, offset, 1);
 *
 * is equals to
 *
 *   char *buf = malloc(size);
 *   iov_to_buf(iov, iovcnt, buf, offset, size);
 *   send(sockfd, buf, size, 0);
 *   free(buf);
 */
static int do_send_recv(int sockfd, struct iovec *iov, int len, int offset,
                        int write)
{
    struct msghdr msg;
    int ret, diff;

    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    len += offset;

    while (iov->iov_len < len) {
        len -= iov->iov_len;

        iov++;
        msg.msg_iovlen++;
    }

    diff = iov->iov_len - len;
    iov->iov_len -= diff;

    while (msg.msg_iov->iov_len <= offset) {
        offset -= msg.msg_iov->iov_len;

        msg.msg_iov++;
        msg.msg_iovlen--;
    }

    msg.msg_iov->iov_base = (char *) msg.msg_iov->iov_base + offset;
    msg.msg_iov->iov_len -= offset;

    if (write) {
        ret = sendmsg(sockfd, &msg, 0);
    } else {
        ret = recvmsg(sockfd, &msg, 0);
    }

    msg.msg_iov->iov_base = (char *) msg.msg_iov->iov_base - offset;
    msg.msg_iov->iov_len += offset;

    iov->iov_len += diff;
    return ret;
}

static int connect_to_sdog(const char *addr, const char *port)
{
    char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
    int fd, ret;
    struct addrinfo hints, *res, *res0;

    if (!addr) {
        addr = SD_DEFAULT_ADDR;
        port = SD_DEFAULT_PORT;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;

    ret = getaddrinfo(addr, port, &hints, &res0);
    if (ret) {
        eprintf("unable to get address info %s, %s\n",
                     addr, strerror(errno));
        return -1;
    }

    for (res = res0; res; res = res->ai_next) {
        ret = getnameinfo(res->ai_addr, res->ai_addrlen, hbuf, sizeof(hbuf),
                          sbuf, sizeof(sbuf), NI_NUMERICHOST | NI_NUMERICSERV);
        if (ret) {
            continue;
        }

        fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (fd < 0) {
            continue;
        }

    reconnect:
        ret = connect(fd, res->ai_addr, res->ai_addrlen);
        if (ret < 0) {
            if (errno == EINTR) {
                goto reconnect;
            }
            break;
        }

        dprintf("connected to %s:%s\n", addr, port);
        goto success;
    }
    fd = -1;
    eprintf("failed connect to %s:%s\n", addr, port);
success:
    freeaddrinfo(res0);
    return fd;
}

static int do_readv_writev(int sockfd, struct iovec *iov, int len,
                           int iov_offset, int write)
{
    int ret;
again:
    ret = do_send_recv(sockfd, iov, len, iov_offset, write);
    if (ret < 0) {
        if (errno == EINTR || errno == EAGAIN) {
            goto again;
        }
        eprintf("failed to recv a rsp, %s\n", strerror(errno));
        return 1;
    }

    iov_offset += ret;
    len -= ret;
    if (len) {
        goto again;
    }

    return 0;
}

/* static int do_readv(int sockfd, struct iovec *iov, int len, int iov_offset) */
/* { */
/*     return do_readv_writev(sockfd, iov, len, iov_offset, 0); */
/* } */

static int do_writev(int sockfd, struct iovec *iov, int len, int iov_offset)
{
    return do_readv_writev(sockfd, iov, len, iov_offset, 1);
}

static int do_read_write(int sockfd, void *buf, int len, int write)
{
    struct iovec iov;

    iov.iov_base = buf;
    iov.iov_len = len;

    return do_readv_writev(sockfd, &iov, len, 0, write);
}

static int do_read(int sockfd, void *buf, int len)
{
    return do_read_write(sockfd, buf, len, 0);
}

/* static int do_write(int sockfd, void *buf, int len) */
/* { */
/*     return do_read_write(sockfd, buf, len, 1); */
/* } */

static int send_req(int sockfd, SheepdogReq *hdr, void *data,
                    unsigned int *wlen)
{
    int ret;
    struct iovec iov[2];

    iov[0].iov_base = hdr;
    iov[0].iov_len = sizeof(*hdr);

    if (*wlen) {
        iov[1].iov_base = data;
        iov[1].iov_len = *wlen;
    }

    ret = do_writev(sockfd, iov, sizeof(*hdr) + *wlen, 0);
    if (ret) {
        eprintf("failed to send a req, %s\n", strerror(errno));
        ret = -1;
    }

    return ret;
}

static int do_req(int sockfd, SheepdogReq *hdr, void *data,
                  unsigned int *wlen, unsigned int *rlen)
{
    int ret;

    ret = send_req(sockfd, hdr, data, wlen);
    if (ret) {
        ret = -1;
        goto out;
    }

    ret = do_read(sockfd, hdr, sizeof(*hdr));
    if (ret) {
        eprintf("failed to get a rsp, %s\n", strerror(errno));
        ret = -1;
        goto out;
    }

    if (*rlen > hdr->data_length) {
        *rlen = hdr->data_length;
    }

    if (*rlen) {
        ret = do_read(sockfd, data, *rlen);
        if (ret) {
            eprintf("failed to get the data, %s\n", strerror(errno));
            ret = -1;
            goto out;
        }
    }
    ret = 0;
out:
    return ret;
}

static int read_write_object(int fd, char *buf, uint64_t oid, int copies,
                             unsigned int datalen, uint64_t offset,
                             int write, int create)
{
    SheepdogObjReq hdr;
    SheepdogObjRsp *rsp = (SheepdogObjRsp *)&hdr;
    unsigned int wlen, rlen;
    int ret;

    memset(&hdr, 0, sizeof(hdr));

    if (write) {
        wlen = datalen;
        rlen = 0;
        hdr.flags = SD_FLAG_CMD_WRITE;
        if (create) {
            hdr.opcode = SD_OP_CREATE_AND_WRITE_OBJ;
        } else {
            hdr.opcode = SD_OP_WRITE_OBJ;
        }
    } else {
        wlen = 0;
        rlen = datalen;
        hdr.opcode = SD_OP_READ_OBJ;
    }
    hdr.oid = oid;
    hdr.data_length = datalen;
    hdr.offset = offset;
    hdr.copies = copies;

    ret = do_req(fd, (SheepdogReq *)&hdr, buf, &wlen, &rlen);
    if (ret) {
        eprintf("failed to send a request to the sheep\n");
        return -1;
    }

    switch (rsp->result) {
    case SD_RES_SUCCESS:
        return 0;
    default:
        eprintf("%s\n", sd_strerror(rsp->result));
        return -1;
    }
}

static int read_object(int fd, char *buf, uint64_t oid, int copies,
                       unsigned int datalen, uint64_t offset)
{
    return read_write_object(fd, buf, oid, copies, datalen, offset, 0, 0);
}

static int write_object(int fd, char *buf, uint64_t oid, int copies,
                        unsigned int datalen, uint64_t offset, int create)
{
    return read_write_object(fd, buf, oid, copies, datalen, offset, 1, create);
}

int sd_io(struct sheepdog_access_info *ai, int write, char *buf,
	  int len, uint64_t offset)
{
	uint32_t vid = ai->inode.vdi_id;
	unsigned long idx = offset / SD_DATA_OBJ_SIZE;
	unsigned long max =
		(offset + len + (SD_DATA_OBJ_SIZE - 1)) / SD_DATA_OBJ_SIZE;
	unsigned obj_offset = offset % SD_DATA_OBJ_SIZE;
	size_t size, rest = len;
	int ret;

	for (; idx < max; idx++) {
		size = SD_DATA_OBJ_SIZE - obj_offset;
		size = min_t(size_t, size, rest);

		if (write)
			ret = write_object(ai->fd, buf + (len - rest),
					   vid_to_data_oid(vid, idx), 1,
					   size, obj_offset, 0);
		else
			ret = read_object(ai->fd, buf + (len - rest),
					  vid_to_data_oid(vid, idx), 1,
					  size, obj_offset);
		if (ret) {
			eprintf("%lu %d\n", idx, ret);
			return -1;
		}

		rest -= size;
		obj_offset = 0;
	}

	return 0;
}

static int find_vdi_name(char *filename, uint32_t snapid,
                         char *tag, uint32_t *vid, int for_snapshot)
{
    int ret, fd;
    SheepdogVdiReq hdr;
    SheepdogVdiRsp *rsp = (SheepdogVdiRsp *)&hdr;
    unsigned int wlen, rlen = 0;
    char buf[SD_MAX_VDI_LEN + SD_MAX_VDI_TAG_LEN];

    fd = connect_to_sdog(NULL, NULL);
    if (fd < 0) {
        return -1;
    }

    memset(buf, 0, sizeof(buf));
    strncpy(buf, filename, SD_MAX_VDI_LEN);
    strncpy(buf + SD_MAX_VDI_LEN, tag, SD_MAX_VDI_TAG_LEN);

    memset(&hdr, 0, sizeof(hdr));
    if (for_snapshot) {
        hdr.opcode = SD_OP_GET_VDI_INFO;
    } else {
        hdr.opcode = SD_OP_LOCK_VDI;
    }
    wlen = SD_MAX_VDI_LEN + SD_MAX_VDI_TAG_LEN;
    hdr.proto_ver = SD_PROTO_VER;
    hdr.data_length = wlen;
    hdr.snapid = snapid;
    hdr.flags = SD_FLAG_CMD_WRITE;

    ret = do_req(fd, (SheepdogReq *)&hdr, buf, &wlen, &rlen);
    if (ret) {
        ret = -1;
        goto out;
    }

    if (rsp->result != SD_RES_SUCCESS) {
        eprintf("cannot get vdi info, %s, %s %d %s\n",
		sd_strerror(rsp->result), filename, snapid, tag);
        ret = -1;
        goto out;
    }
    *vid = rsp->vdi_id;

    ret = 0;
out:
    close(fd);
    return ret;
}

int sd_open(struct sheepdog_access_info *ai, char *filename, int flags)
{
    int ret, fd;
    uint32_t vid = 0;
    char vdi[SD_MAX_VDI_LEN], tag[SD_MAX_VDI_TAG_LEN];

    memset(vdi, 0, sizeof(vdi));
    memset(tag, 0, sizeof(tag));
    /* if (parse_vdiname(s, filename, vdi, &snapid, tag) < 0) { */
    /*     goto out; */
    /* } */
    /* s->fd = get_sheep_fd(s); */
    /* if (s->fd < 0) { */
    /*     goto out; */
    /* } */

    ret = find_vdi_name(filename, CURRENT_VDI_ID, tag, &vid, 0);
    if (ret) {
        goto out;
    }

    /* if (snapid) { */
    /*     dprintf("%" PRIx32 " snapshot inode was open.\n", vid); */
    /*     s->is_snapshot = 1; */
    /* } */

    fd = connect_to_sdog(NULL, NULL);
    if (fd < 0) {
        eprintf("failed to connect\n");
        goto out;
    }

    ret = read_object(fd, (char *)&ai->inode, vid_to_vdi_oid(vid),
		      0, SD_INODE_SIZE, 0);

    ai->fd = fd;

    if (ret) {
        goto out;
    }

    /* memcpy(&s->inode, buf, sizeof(s->inode)); */
    /* s->min_dirty_data_idx = UINT32_MAX; */
    /* s->max_dirty_data_idx = 0; */

    /* bs->total_sectors = s->inode.vdi_size / SECTOR_SIZE; */
    /* strncpy(s->name, vdi, sizeof(s->name)); */
    /* qemu_free(buf); */
    return 0;
out:
/*     qemu_aio_set_fd_handler(s->fd, NULL, NULL, NULL, NULL, NULL); */
/*     if (s->fd >= 0) { */
/*         closesocket(s->fd); */
/*     } */
/*     qemu_free(buf); */
    return -1;
}

