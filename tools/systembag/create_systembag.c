// Create a fresh system keybag on a mounted, protected Data volume.
// Runs on the iOS 12 ramdisk; MobileKeyBag is loaded at runtime.
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define DEFAULT_FRAMEWORK "/System/Library/PrivateFrameworks/MobileKeyBag.framework/MobileKeyBag"

typedef int (*create_system_t)(void *, const char *);

int main(int argc, char **argv) {
    if ((argc != 3 && argc != 4) || strcmp(argv[1], "--create") != 0) {
        fprintf(stderr, "usage: %s --create MOUNTPOINT [MOBILEKEYBAG_PATH]\n", argv[0]);
        return 2;
    }
    const char *mountpoint = argv[2];
    const char *framework = argc == 4 ? argv[3] : DEFAULT_FRAMEWORK;
    char path[1024];
    if ((unsigned)snprintf(path, sizeof(path), "%s/keybags/systembag.kb", mountpoint) >= sizeof(path))
        return 2;

    struct stat st;
    if (lstat(path, &st) == 0) {
        fprintf(stderr, "systembag already exists: %s\n", path);
        return 3;
    }
    if (errno != ENOENT) {
        perror(path);
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
    if (stat(path, &st) != 0) {
        perror(path);
        return 6;
    }
    printf("%s bytes=%lld uid=%u gid=%u mode=%o\n", path, (long long)st.st_size,
           st.st_uid, st.st_gid, st.st_mode & 07777);
    sync();
    return 0;
}
