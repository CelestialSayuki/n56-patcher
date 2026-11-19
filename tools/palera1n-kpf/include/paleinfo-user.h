/* Offline-delivered user-mode ABI for upstream paleinfo v2 (not kerninfo).
 * Caller supplies an already-open ramdisk FD; this header never opens a device,
 * writes storage, installs a bootstrap, or requests kernel memory access.
 * For /dev/rdisk0 transport the upstream format stores the metadata offset in
 * the first LE uint32 and places the 48-byte structure at that byte offset.
 */
#ifndef N56_PALEINFO_USER_H
#define N56_PALEINFO_USER_H
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include "../vendor/include/paleinfo.h"

_Static_assert(sizeof(struct paleinfo) == 48, "paleinfo v2 ABI drift");

static inline int n56_paleinfo_pread_exact(int fd, void *buffer, size_t size, off_t offset) {
    unsigned char *out = buffer;
    while (size) {
        ssize_t n = pread(fd, out, size, offset);
        if (n < 0) { if (errno == EINTR) continue; return -1; }
        if (!n) { errno = EIO; return -1; }
        out += n; size -= (size_t)n; offset += n;
    }
    return 0;
}

static inline int n56_paleinfo_validate(const struct paleinfo *info) {
    if (info->magic != PALEINFO_MAGIC || info->version != PALEINFO_VERSION ||
        !memchr(info->rootdev, 0, sizeof(info->rootdev)) ||
        info->kbase != UINT64_C(0xfffffff007004000) + info->kslide ||
        (info->kslide & 0x3fff)) {
        errno = EINVAL; return -1;
    }
    return 0;
}

static inline int n56_paleinfo_read_fd(int fd, struct paleinfo *info) {
    unsigned char header[4];
    if (n56_paleinfo_pread_exact(fd, header, sizeof(header), 0)) return -1;
    uint32_t offset = (uint32_t)header[0] | (uint32_t)header[1] << 8 |
                      (uint32_t)header[2] << 16 | (uint32_t)header[3] << 24;
    if (offset < 4) { errno = EINVAL; return -1; }
    if (n56_paleinfo_pread_exact(fd, info, sizeof(*info), offset)) return -1;
    return n56_paleinfo_validate(info);
}
#endif
