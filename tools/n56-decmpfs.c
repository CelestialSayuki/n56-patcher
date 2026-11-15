/*
 * n56-decmpfs <dest-root>
 *
 * 在 ramdisk 上按苹果透明压缩（decmpfs）的存法写文件，保留 IPSW 镜像里原有的压缩数据。
 * 主机端（core/decmpfs.py）从只读挂载的镜像读出每个文件的 com.apple.decmpfs 头和资源分支，
 * 经 stdin 流过来；这里写成“数据分支为空 + 两个扩展属性 + UF_COMPRESSED”，再设属主、
 * 权限和时间，最后按普通方式读回、核对大小与 sha256。任何一项不符就退出非零。
 *
 * 流格式（小端）：
 *   "N56DECMP1\n"
 *   重复：u32 路径长度（0 表示结束）| 路径（相对 dest-root）| u32 mode | u32 uid | u32 gid
 *         | i64 mtime 秒 | i64 mtime 纳秒 | u32 头长度 | 头 | u64 资源分支长度 | 资源分支
 *         | 32 字节 sha256（解压后的内容）
 */
#include <CommonCrypto/CommonDigest.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/xattr.h>
#include <unistd.h>

#define MAGIC "N56DECMP1\n"

static void fail(const char *path, const char *what) {
    fprintf(stderr, "n56-decmpfs: %s: %s: %s\n", path ? path : "-", what, strerror(errno));
    exit(1);
}

static void read_exact(void *buf, size_t len) {
    uint8_t *p = buf;
    while (len) {
        size_t n = fread(p, 1, len, stdin);
        if (n == 0) { errno = EIO; fail(NULL, "流提前结束"); }
        p += n; len -= n;
    }
}

static uint32_t u32(void) { uint32_t v; read_exact(&v, 4); return v; }
static uint64_t u64(void) { uint64_t v; read_exact(&v, 8); return v; }

static void *blob(size_t len) {
    void *p = malloc(len ? len : 1);
    if (!p) fail(NULL, "内存不足");
    read_exact(p, len);
    return p;
}

/* 与 GNU tar 隐式建父目录一致：root 属主、0755（ramdisk 上 umask 设为 022）。 */
static void make_parents(char *path) {
    for (char *s = strchr(path + 1, '/'); s; s = strchr(s + 1, '/')) {
        *s = 0;
        if (mkdir(path, 0755) && errno != EEXIST) fail(path, "mkdir");
        *s = '/';
    }
}

/* --sha256 <文件>：打印文件内容的 sha256（ramdisk 没有任何哈希工具，大文件分块写完用它核对）。 */
static int sha256_file(const char *path) {
    static uint8_t buf[1 << 20];
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) fail(path, "open");
    CC_SHA256_CTX sha;
    CC_SHA256_Init(&sha);
    for (;;) {
        ssize_t n = read(fd, buf, sizeof buf);
        if (n < 0) fail(path, "read");
        if (n == 0) break;
        CC_SHA256_Update(&sha, buf, (CC_LONG)n);
    }
    close(fd);
    uint8_t digest[32];
    CC_SHA256_Final(digest, &sha);
    for (int i = 0; i < 32; i++) printf("%02x", digest[i]);
    printf("\n");
    return 0;
}

int main(int argc, char **argv) {
    if (argc == 3 && !strcmp(argv[1], "--sha256")) return sha256_file(argv[2]);
    if (argc != 2) { fprintf(stderr, "usage: n56-decmpfs <dest-root> | --sha256 <file>\n"); return 2; }
    umask(022);
    char magic[sizeof(MAGIC) - 1];
    read_exact(magic, sizeof magic);
    if (memcmp(magic, MAGIC, sizeof magic)) { errno = EINVAL; fail(NULL, "流格式不符"); }
    unsigned long long files = 0, logical = 0, stored = 0;
    static uint8_t chunk[1 << 20];
    for (;;) {
        uint32_t path_len = u32();
        if (!path_len) break;
        char *rel = malloc(path_len + 1);
        if (!rel) fail(NULL, "内存不足");
        read_exact(rel, path_len);
        rel[path_len] = 0;
        size_t full_len = strlen(argv[1]) + path_len + 2;
        char *path = malloc(full_len);
        snprintf(path, full_len, "%s/%s", argv[1], rel);
        uint32_t mode = u32(), uid = u32(), gid = u32();
        int64_t sec = (int64_t)u64(), nsec = (int64_t)u64();
        uint32_t hdr_len = u32();
        uint8_t *hdr = blob(hdr_len);
        uint64_t rsrc_len = u64();
        uint8_t *rsrc = blob(rsrc_len);
        uint8_t want[32];
        read_exact(want, sizeof want);
        if (hdr_len < 16) { errno = EINVAL; fail(path, "decmpfs 头太短"); }
        uint64_t size;
        memcpy(&size, hdr + 8, 8);

        make_parents(path);
        if (unlink(path) && errno != ENOENT) fail(path, "unlink");
        int fd = open(path, O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW, 0600);
        if (fd < 0) fail(path, "open");
        if (rsrc_len && fsetxattr(fd, XATTR_RESOURCEFORK_NAME, rsrc, rsrc_len, 0, XATTR_SHOWCOMPRESSION))
            fail(path, "写资源分支");
        if (fsetxattr(fd, "com.apple.decmpfs", hdr, hdr_len, 0, XATTR_SHOWCOMPRESSION))
            fail(path, "写 decmpfs 头");
        struct stat st;
        if (fstat(fd, &st) || fchflags(fd, st.st_flags | UF_COMPRESSED)) fail(path, "设压缩标志");
        if (fchown(fd, uid, gid)) fail(path, "chown");
        if (fchmod(fd, mode & 07777)) fail(path, "chmod");
        close(fd);
        struct timeval times[2] = {{sec, (int)(nsec / 1000)}, {sec, (int)(nsec / 1000)}};
        if (lutimes(path, times)) fail(path, "utimes");

        /* 读回：经内核解压后的内容必须与镜像原文件一致。 */
        fd = open(path, O_RDONLY | O_NOFOLLOW);
        if (fd < 0) fail(path, "回读 open");
        CC_SHA256_CTX sha;
        CC_SHA256_Init(&sha);
        uint64_t got = 0;
        for (;;) {
            ssize_t n = read(fd, chunk, sizeof chunk);
            if (n < 0) fail(path, "回读");
            if (n == 0) break;
            CC_SHA256_Update(&sha, chunk, (CC_LONG)n);
            got += (uint64_t)n;
        }
        close(fd);
        uint8_t have[32];
        CC_SHA256_Final(have, &sha);
        if (got != size || memcmp(have, want, 32)) { errno = EIO; fail(path, "回读内容与镜像不符"); }

        files++; logical += size; stored += hdr_len + rsrc_len;
        free(rel); free(path); free(hdr); free(rsrc);
    }
    printf("n56-decmpfs: %llu files, logical %llu bytes, stored %llu bytes\n", files, logical, stored);
    return 0;
}
