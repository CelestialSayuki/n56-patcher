// Create a fresh system keybag on a mounted, protected Data volume.
// Runs on the iOS 12 ramdisk; MobileKeyBag is loaded at runtime.
//
// Also implements `--load MOUNTPOINT` to reload an existing systembag.kb into
// SEP on a fresh ramdisk boot. This shares the exact same Mach-O/signature as
// the working `--create` helper.
//
// IMPORTANT (Linux cross-build): core/iosbuild.py builds this helper with
// -nostdlib and links libSystem via tools/ios-minimal-sdk/lib/libSystem.tbd.
// Only function-style libSystem symbols are referenced: no stderr/stdout/
// errno/perror data symbols. Formatted output goes through snprintf() into a
// stack buffer followed by write(2) / write(1).
//
// Contract V2 (checked by patches/ios15/impl/rootfs/keybag_boot.validate_helper):
//   - refuse when keybags/systembag.kb.writing exists (including a dangling
//     symlink): native code must recover it, never replace it with a new bag;
//   - after MKBKeyBagCreateSystem succeeds, read the bag back without following
//     links (regular file, same inode, non-empty, bounded size, fully readable).
#include <dlfcn.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CONTRACT "N56_SYSTEMBAG_RECOVERY_GUARD_V2"
#define DEFAULT_FRAMEWORK "/System/Library/PrivateFrameworks/MobileKeyBag.framework/MobileKeyBag"
#define COREFOUNDATION "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
#define MAX_BAG_BYTES (16LL * 1024 * 1024)

/* Offsets inside the iOS 12.5.8 (16H88) MobileKeyBag binary. */
#define OFF_MKB_KEYBAG_CREATE_SYSTEM 0x8df4
#define OFF_KB_LOAD_LOAD_KEYBAG_FILE 0x3130
#define OFF_GET_DATA                 0xf104
#define OFF_AKS_LOAD_BAG             0x1d278
#define OFF_AKS_SET_SYSTEM           0x1deb4
#define OFF_AKS_GET_SYSTEM           0x1dd40
#define OFF_KB_MAP_DEVICE_BAG        0x604c
#define OFF_AKS_UNLOAD_BAG           0x1d3ac
#define OFF_KEYBAG_KEYS_CFSTRING     0x35cf8

typedef int (*create_system_t)(void *, const char *, unsigned int);
typedef void (*set_log_t)(void (*)(const char *));
typedef int (*get_system_t)(unsigned int, unsigned int *);
typedef int (*load_file_t)(const char *, const char *, void **);
typedef void *(*get_data_t)(void *, void *);
typedef const unsigned char *(*cfdata_bytes_t)(void *);
typedef long (*cfdata_length_t)(void *);
typedef void (*cfrelease_t)(void *);
typedef int (*aks_load_bag_t)(const void *, long, unsigned int *);
typedef int (*set_system_t)(unsigned int, unsigned int);
typedef int (*map_device_bag_t)(const char *);
typedef int (*unload_bag_t)(unsigned int);

static void write_all(int fd, const char *s, unsigned long n) {
    while (n) {
        ssize_t w = write(fd, s, n);
        if (w <= 0) return;
        s += w;
        n -= (unsigned long)w;
    }
}

// snprintf 与 write 都是函数符号；展开后不引用任何 libc 数据全局变量。
#define EMIT(fd, ...) do {                                            \
    char _n56_buf[1024];                                              \
    int _n56_len = snprintf(_n56_buf, sizeof(_n56_buf), __VA_ARGS__); \
    if (_n56_len > 0) {                                               \
        unsigned long _n56_n = (unsigned long)_n56_len;               \
        if (_n56_n > sizeof(_n56_buf) - 1)                            \
            _n56_n = sizeof(_n56_buf) - 1;                            \
        write_all((fd), _n56_buf, _n56_n);                            \
    }                                                                 \
} while (0)

#define ERR(...) EMIT(2, __VA_ARGS__)
#define OUT(...) EMIT(1, __VA_ARGS__)

static void *offset_ptr(void *base, unsigned long off) {
    return (void *)((unsigned char *)base + off);
}

/* MobileKeyBag's own debug log. MKBSetLogFunction() installs this callback. */
static void mkb_log(const char *msg) {
    if (!msg) return;
    unsigned long n = 0;
    while (msg[n] && n < 4096) n++;
    write_all(1, "MKB: ", 5);
    write_all(1, msg, n);
    write_all(1, "\n", 1);
}

// Reload an existing systembag into SEP for the current ramdisk session.
// Inverse of KBSaveSystemBagHandle(): read the plist, take its "KeyBagKeys"
// CFData (the aks_save_bag() blob), aks_load_bag(), aks_set_system(),
// KBMapDeviceBag(), then drop our local AKS bag reference.
static int load_mode(const char *mountpoint, const char *framework) {
    char dir[1024];
    if ((unsigned)snprintf(dir, sizeof(dir), "%s/keybags", mountpoint) >= sizeof(dir))
        return 2;

    OUT("load_systembag: start dir=%s mount=%s\n", dir, mountpoint);
    void *mkb = dlopen(framework, RTLD_NOW | RTLD_GLOBAL);
    OUT("load_systembag: dlopen MobileKeyBag=%p\n", mkb);
    if (!mkb) {
        ERR("dlopen: %s\n", dlerror());
        return 4;
    }
    void *anchor = dlsym(mkb, "MKBKeyBagCreateSystem");
    OUT("load_systembag: dlsym anchor=%p\n", anchor);
    if (!anchor) {
        ERR("dlsym MKBKeyBagCreateSystem: %s\n", dlerror());
        return 5;
    }
    void *base = (void *)((unsigned char *)anchor - OFF_MKB_KEYBAG_CREATE_SYSTEM);
    OUT("load_systembag: base=%p\n", base);

    set_log_t set_log = (set_log_t)dlsym(mkb, "MKBSetLogFunction");
    if (set_log) {
        set_log(mkb_log);
        OUT("load_systembag: MobileKeyBag debug log enabled\n");
    }

    void *cf = dlopen(COREFOUNDATION, RTLD_NOW | RTLD_GLOBAL);
    cfdata_bytes_t data_bytes = cf ? (cfdata_bytes_t)dlsym(cf, "CFDataGetBytePtr") : 0;
    cfdata_length_t data_length = cf ? (cfdata_length_t)dlsym(cf, "CFDataGetLength") : 0;
    cfrelease_t release = cf ? (cfrelease_t)dlsym(cf, "CFRelease") : 0;
    OUT("load_systembag: cf=%p CFDataGetBytePtr=%p CFDataGetLength=%p CFRelease=%p\n",
        cf, (void *)data_bytes, (void *)data_length, (void *)release);
    if (!data_bytes || !data_length || !release) {
        ERR("dlsym CoreFoundation failed\n");
        return 6;
    }

    load_file_t load_file = (load_file_t)offset_ptr(base, OFF_KB_LOAD_LOAD_KEYBAG_FILE);
    get_data_t get_data = (get_data_t)offset_ptr(base, OFF_GET_DATA);
    aks_load_bag_t load_bag = (aks_load_bag_t)offset_ptr(base, OFF_AKS_LOAD_BAG);
    set_system_t set_system = (set_system_t)offset_ptr(base, OFF_AKS_SET_SYSTEM);
    get_system_t get_system = (get_system_t)offset_ptr(base, OFF_AKS_GET_SYSTEM);
    map_device_bag_t map_device = (map_device_bag_t)offset_ptr(base, OFF_KB_MAP_DEVICE_BAG);
    unload_bag_t unload_bag = (unload_bag_t)offset_ptr(base, OFF_AKS_UNLOAD_BAG);
    void *keys_key = offset_ptr(base, OFF_KEYBAG_KEYS_CFSTRING);

    OUT("load_systembag: call KBLoadLoadKeyBagFile\n");
    void *obj = 0;
    int rc = load_file(dir, "systembag", &obj);
    OUT("load_systembag: KBLoadLoadKeyBagFile -> %d obj=%p\n", rc, obj);
    if (rc != 0 || !obj) {
        ERR("KBLoadLoadKeyBagFile(%s, systembag) -> %d obj=%p\n", dir, rc, obj);
        return 7;
    }
    /* __getData() returns a non-owned CFDataRef from the dictionary. */
    void *blob = get_data(obj, keys_key);
    OUT("load_systembag: KeyBagKeys blob=%p\n", blob);
    if (!blob) {
        ERR("__getData(obj, KeyBagKeys) failed\n");
        release(obj);
        return 8;
    }
    long length = data_length(blob);
    const unsigned char *bytes = data_bytes(blob);
    OUT("load_systembag: blob len=%ld bytes=%p\n", length, (const void *)bytes);
    if (length <= 0 || !bytes) {
        ERR("bad KeyBagKeys blob: len=%ld bytes=%p\n", length, (const void *)bytes);
        release(obj);
        return 9;
    }

    OUT("load_systembag: call aks_load_bag\n");
    unsigned int handle = 0;
    rc = load_bag(bytes, length, &handle);
    OUT("aks_load_bag(KeyBagKeys len=%ld) -> %d handle=0x%x\n", length, rc, handle);
    if (rc != 0 || !handle) {
        ERR("aks_load_bag failed: %d\n", rc);
        release(obj);
        return 10;
    }

    OUT("load_systembag: call aks_set_system\n");
    rc = set_system(handle, 0);
    OUT("aks_set_system(0x%x) -> %d\n", handle, rc);
    if (rc != 0) {
        ERR("aks_set_system failed: %d\n", rc);
        unload_bag(handle);
        release(obj);
        return 11;
    }
    unsigned int current = 0;
    int grc = get_system(0, &current);
    OUT("aks_get_system after set -> %d current=0x%x\n", grc, current);

    OUT("load_systembag: call KBMapDeviceBag\n");
    rc = map_device(mountpoint);
    OUT("KBMapDeviceBag(%s) -> %d\n", mountpoint, rc);
    unload_bag(handle);
    current = 0;
    grc = get_system(0, &current);
    OUT("aks_get_system after unload -> %d current=0x%x\n", grc, current);
    release(obj);
    if (rc != 0) {
        ERR("KBMapDeviceBag failed: %d\n", rc);
        return 12;
    }

    OUT("systembag loaded from %s/systembag.kb\n", dir);
    return 0;
}

// 0: absent, 1: present (file or any link).
// 不用 errno 这个 libc 数据符号：ramdisk 的 flat namespace 无法解析它。
// 任何 lstat 失败都按“不存在”处理；真正的权限/IO 问题会在后续 create/readback 暴露。
static int exists_nofollow(const char *path) {
    struct stat st;
    return lstat(path, &st) == 0 ? 1 : 0;
}

// Secure readback of the bag the native API just saved.
// All output goes through ERR()/OUT() so no stderr/stdout data symbols are needed.
static int readback(const char *path) {
    struct stat link, st;
    if (lstat(path, &link) != 0) {
        ERR("systembag lstat failed: %s\n", path);
        return 6;
    }
    if (!S_ISREG(link.st_mode)) {
        ERR("systembag is not a regular file: %s\n", path);
        return 7;
    }
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) {
        ERR("systembag open failed: %s\n", path);
        return 7;
    }
    if (fstat(fd, &st) != 0 || st.st_dev != link.st_dev || st.st_ino != link.st_ino || !S_ISREG(st.st_mode)) {
        ERR("systembag changed during readback: %s\n", path);
        close(fd);
        return 7;
    }
    if (st.st_size <= 0 || st.st_size > MAX_BAG_BYTES) {
        ERR("systembag size out of range: %lld\n", (long long)st.st_size);
        close(fd);
        return 7;
    }
    char buffer[4096];
    long long total = 0;
    for (;;) {
        ssize_t got = read(fd, buffer, sizeof(buffer));
        if (got < 0) {
            ERR("systembag read failed: %s\n", path);
            close(fd);
            return 7;
        }
        if (got == 0)
            break;
        total += got;
    }
    close(fd);
    if (total != (long long)st.st_size) {
        ERR("systembag readback size mismatch: read=%lld stat=%lld\n",
            total, (long long)st.st_size);
        return 7;
    }
    OUT("%s bytes=%lld uid=%u gid=%u mode=%o readback=ok\n", path, (long long)st.st_size,
        st.st_uid, st.st_gid, st.st_mode & 07777);
    return 0;
}

int main(int argc, char **argv) {
    const char *framework = DEFAULT_FRAMEWORK;

    if (argc >= 2 && strcmp(argv[1], "--load") == 0) {
        const char *mountpoint = argc > 2 ? argv[2] : "/mnt7";
        framework = argc > 3 ? argv[3] : DEFAULT_FRAMEWORK;
        return load_mode(mountpoint, framework);
    }

    if ((argc != 3 && argc != 4) || strcmp(argv[1], "--create") != 0) {
        ERR("usage: %s --create MOUNTPOINT [MOBILEKEYBAG_PATH] | "
            "%s --load MOUNTPOINT [MOBILEKEYBAG_PATH]\n", argv[0], argv[0]);
        return 2;
    }
    OUT("contract=" CONTRACT "\n");
    // The bag holds key material: create it owner-only (0600), not umask 022's 0644.
    umask(077);
    const char *mountpoint = argv[2];
    if (argc == 4)
        framework = argv[3];
    char path[1024], recovery[1040];
    if ((unsigned)snprintf(path, sizeof(path), "%s/keybags/systembag.kb", mountpoint) >= sizeof(path))
        return 2;
    if ((unsigned)snprintf(recovery, sizeof(recovery), "%s.writing", path) >= sizeof(recovery))
        return 2;

    if (exists_nofollow(path)) {
        ERR("systembag already exists: %s\n", path);
        return 3;
    }
    if (exists_nofollow(recovery)) {
        ERR("systembag recovery file exists, refusing to create: %s\n", recovery);
        return 3;
    }

    void *handle = dlopen(framework, RTLD_NOW | RTLD_GLOBAL);
    if (!handle) {
        ERR("dlopen: %s\n", dlerror());
        return 4;
    }

    set_log_t set_log = (set_log_t)dlsym(handle, "MKBSetLogFunction");
    if (set_log) {
        set_log(mkb_log);
        OUT("MobileKeyBag debug log enabled\n");
    }

    void *anchor = dlsym(handle, "MKBKeyBagCreateSystem");
    create_system_t create = (create_system_t)anchor;
    if (!create) {
        ERR("dlsym: %s\n", dlerror());
        return 4;
    }
    void *base = (void *)((unsigned char *)anchor - OFF_MKB_KEYBAG_CREATE_SYSTEM);
    get_system_t get_system = (get_system_t)offset_ptr(base, OFF_AKS_GET_SYSTEM);

    OUT("MKBKeyBagCreateSystem(NULL, %s, 0) via %s\n", mountpoint, framework);
    int result = create(NULL, mountpoint, 0);
    OUT("MKBKeyBagCreateSystem result=%d hex=0x%08x\n", result, result);
    if (result != 0)
        return 5;
    /* A zero result means KBMapDeviceBag() succeeded. Log the SEP-visible
       handle for diagnosis, but let the secure readback + caller's real write
       preflight be the final gates. */
    unsigned int current = 0;
    int grc = get_system ? get_system(0, &current) : -1;
    OUT("aks_get_system after create -> %d current=0x%x\n", grc, current);

    sync();
    int checked = readback(path);
    if (checked != 0)
        return checked;
    // Report only: the native save path owns this file's lifecycle.
    if (exists_nofollow(recovery))
        OUT("note: recovery file still present after native save: %s\n", recovery);
    sync();
    return 0;
}
