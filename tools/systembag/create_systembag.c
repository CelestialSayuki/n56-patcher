// Create a fresh system keybag on a mounted, protected Data volume.
// Runs on the iOS 12 ramdisk; MobileKeyBag is loaded at runtime.
//
// Contract V2 (checked by patches/ios15/impl/rootfs/keybag_boot.validate_helper):
//   - refuse when keybags/systembag.kb.writing (a native save in progress or an
//     interrupted one) exists, including a dangling symlink: it must be
//     recovered by native code, never replaced by a new bag;
//   - after MKBKeyBagCreateSystem reports success, read the bag back without
//     following links (regular file, same inode as the path, non-empty,
//     bounded size, every byte readable) before reporting success.
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CONTRACT "N56_SYSTEMBAG_RECOVERY_GUARD_V2"
#define DEFAULT_FRAMEWORK "/System/Library/PrivateFrameworks/MobileKeyBag.framework/MobileKeyBag"
#define MAX_BAG_BYTES (16LL * 1024 * 1024)

typedef int (*create_system_t)(void *, const char *);

// 0: absent, 1: present (file or any link), -1: query failed.
static int exists_nofollow(const char *path) {
    struct stat st;
    if (lstat(path, &st) == 0)
        return 1;
    if (errno == ENOENT)
        return 0;
    perror(path);
    return -1;
}

// Secure readback of the bag the native API just saved.
static int readback(const char *path) {
    struct stat link, st;
    if (lstat(path, &link) != 0) {
        perror(path);
        return 6;
    }
    if (!S_ISREG(link.st_mode)) {
        fprintf(stderr, "systembag is not a regular file: %s\n", path);
        return 7;
    }
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) {
        perror(path);
        return 7;
    }
    if (fstat(fd, &st) != 0 || st.st_dev != link.st_dev || st.st_ino != link.st_ino || !S_ISREG(st.st_mode)) {
        fprintf(stderr, "systembag changed during readback: %s\n", path);
        close(fd);
        return 7;
    }
    if (st.st_size <= 0 || st.st_size > MAX_BAG_BYTES) {
        fprintf(stderr, "systembag size out of range: %lld\n", (long long)st.st_size);
        close(fd);
        return 7;
    }
    char buffer[4096];
    long long total = 0;
    for (;;) {
        ssize_t got = read(fd, buffer, sizeof(buffer));
        if (got < 0) {
            if (errno == EINTR)
                continue;
            perror(path);
            close(fd);
            return 7;
        }
        if (got == 0)
            break;
        total += got;
    }
    close(fd);
    if (total != (long long)st.st_size) {
        fprintf(stderr, "systembag readback size mismatch: read=%lld stat=%lld\n", total, (long long)st.st_size);
        return 7;
    }
    printf("%s bytes=%lld uid=%u gid=%u mode=%o readback=ok\n", path, (long long)st.st_size,
           st.st_uid, st.st_gid, st.st_mode & 07777);
    return 0;
}

int main(int argc, char **argv) {
    if ((argc != 3 && argc != 4) || strcmp(argv[1], "--create") != 0) {
        fprintf(stderr, "usage: %s --create MOUNTPOINT [MOBILEKEYBAG_PATH]\n", argv[0]);
        return 2;
    }
    printf("contract=" CONTRACT "\n");
    // The bag holds key material: create it owner-only (0600), not umask 022's 0644.
    umask(077);
    const char *mountpoint = argv[2];
    const char *framework = argc == 4 ? argv[3] : DEFAULT_FRAMEWORK;
    char path[1024], recovery[1040];
    if ((unsigned)snprintf(path, sizeof(path), "%s/keybags/systembag.kb", mountpoint) >= sizeof(path))
        return 2;
    if ((unsigned)snprintf(recovery, sizeof(recovery), "%s.writing", path) >= sizeof(recovery))
        return 2;

    int state = exists_nofollow(path);
    if (state != 0) {
        if (state > 0)
            fprintf(stderr, "systembag already exists: %s\n", path);
        return 3;
    }
    state = exists_nofollow(recovery);
    if (state != 0) {
        if (state > 0)
            fprintf(stderr, "systembag recovery file exists, refusing to create: %s\n", recovery);
        return 3;
    }

    void *handle = dlopen(framework, RTLD_NOW | RTLD_GLOBAL);
    if (!handle) {
        fprintf(stderr, "dlopen: %s\n", dlerror());
        return 4;
    }
    create_system_t create = (create_system_t)dlsym(handle, "MKBKeyBagCreateSystem");
    if (!create) {
        fprintf(stderr, "dlsym: %s\n", dlerror());
        return 4;
    }

    printf("MKBKeyBagCreateSystem(NULL, %s) via %s\n", mountpoint, framework);
    fflush(stdout);
    int result = create(NULL, mountpoint);
    printf("MKBKeyBagCreateSystem result=%d hex=0x%08x\n", result, result);
    if (result != 0)
        return 5;
    sync();
    int checked = readback(path);
    if (checked != 0)
        return checked;
    // Report only: the native save path owns this file's lifecycle.
    if (exists_nofollow(recovery) > 0)
        printf("note: recovery file still present after native save: %s\n", recovery);
    fflush(stdout);
    sync();
    return 0;
}
