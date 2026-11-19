/* System15 basic-rootful runtime identity guard. No kernel-RW or fake paleinfo. */
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/attr.h>
#include <sys/mount.h>
#include <sys/snapshot.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>
#define JSMN_STATIC
#define JSMN_PARENT_LINKS
#include "jsmn.h"
#include "apfs_mount_args.h"

static int allow_readonly_root;

typedef struct { char *text; jsmntok_t tokens[256]; int count; } document;

static int failure(const char *message) {
    fprintf(stderr, "n56 rootful runtime: %s (errno=%d)\n", message, errno);
    return 78;
}

static int read_owned(const char *path, char **output, size_t limit) {
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    struct stat st;
    if (fd < 0) return -1;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_uid != 0 ||
        (st.st_mode & (S_IWGRP | S_IWOTH)) || st.st_size <= 0 || (uint64_t)st.st_size > limit) {
        close(fd); return -1;
    }
    size_t length = (size_t)st.st_size, done = 0;
    char *buffer = malloc(length + 1);
    if (!buffer) { close(fd); return -1; }
    while (done < length) {
        ssize_t n = read(fd, buffer + done, length - done);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { free(buffer); close(fd); return -1; }
        done += (size_t)n;
    }
    buffer[length] = 0; close(fd); *output = buffer; return 0;
}

static int load_document(const char *path, document *d) {
    if (read_owned(path, &d->text, 32768)) return -1;
    jsmn_parser parser; jsmn_init(&parser);
    d->count = jsmn_parse(&parser, d->text, strlen(d->text), d->tokens, 256);
    if (d->count < 1 || d->tokens[0].type != JSMN_OBJECT) { free(d->text); return -1; }
    return 0;
}

static int token_equals(const document *d, int i, const char *value) {
    int n = d->tokens[i].end - d->tokens[i].start;
    return n >= 0 && (size_t)n == strlen(value) && !memcmp(d->text + d->tokens[i].start, value, (size_t)n);
}

static int root_value(const document *d, const char *key) {
    int result = -1;
    for (int i = 1; i + 1 < d->count; ++i) {
        if (d->tokens[i].parent == 0 && d->tokens[i].type == JSMN_STRING && token_equals(d, i, key)) {
            if (result >= 0) return -1;
            result = i + 1;
        }
    }
    return result;
}

static int string_value(const document *d, const char *key, char *out, size_t capacity) {
    int i = root_value(d, key);
    if (i < 0 || d->tokens[i].type != JSMN_STRING) return -1;
    int n = d->tokens[i].end - d->tokens[i].start;
    if (n < 0 || (size_t)n >= capacity) return -1;
    memcpy(out, d->text + d->tokens[i].start, (size_t)n); out[n] = 0;
    if (strchr(out, '\\') || strchr(out, '"')) return -1;
    return 0;
}

static int slice_value(const document *d, const char *key) {
    char buffer[8]; int i = root_value(d, key);
    if (i < 0 || d->tokens[i].type != JSMN_PRIMITIVE) return -1;
    int n = d->tokens[i].end - d->tokens[i].start;
    if (n < 1 || n >= (int)sizeof(buffer)) return -1;
    memcpy(buffer, d->text + d->tokens[i].start, (size_t)n); buffer[n] = 0;
    for (int j = 0; j < n; ++j) if (buffer[j] < '0' || buffer[j] > '9') return -1;
    unsigned long value = strtoul(buffer, NULL, 10);
    return value >= 4 && value <= 100 ? (int)value : -1;
}

static int normalize_uuid(const char *text, uint8_t out[16]) {
    int nybble = 0; unsigned value = 0;
    for (const char *p = text; *p; ++p) {
        if (*p == '-') continue;
        unsigned digit;
        if (*p >= '0' && *p <= '9') digit = (unsigned)(*p - '0');
        else if (*p >= 'a' && *p <= 'f') digit = (unsigned)(*p - 'a' + 10);
        else if (*p >= 'A' && *p <= 'F') digit = (unsigned)(*p - 'A' + 10);
        else return -1;
        if (nybble >= 32) return -1;
        value = value * 16 + digit;
        if (nybble & 1) { out[nybble / 2] = (uint8_t)value; value = 0; }
        ++nybble;
    }
    if (nybble != 32) return -1;
    unsigned nonzero = 0; for (int i = 0; i < 16; ++i) nonzero |= out[i];
    return nonzero ? 0 : -1;
}

static int volume_uuid(const char *path, uint8_t out[16]) {
    struct attrlist attrs; memset(&attrs, 0, sizeof(attrs));
    attrs.bitmapcount = ATTR_BIT_MAP_COUNT; attrs.volattr = ATTR_VOL_INFO | ATTR_VOL_UUID;
    struct { uint32_t length; uint8_t uuid[16]; } result;
    memset(&result, 0, sizeof(result));
    if (getattrlist(path, &attrs, &result, sizeof(result), 0) || result.length != sizeof(result)) return -1;
    memcpy(out, result.uuid, 16); return 0;
}

static int check_volume(const char *path, int slice, const uint8_t expected[16], int system) {
    struct statfs fs; uint8_t actual[16]; char device[64];
    snprintf(device, sizeof(device), "/dev/disk0s1s%d", slice);
    if (statfs(path, &fs) || strcmp(fs.f_fstypename, "apfs") ||
        strcmp(fs.f_mntfromname, device) || strcmp(fs.f_mntonname, system ? "/" : "/private/var")) return -1;
    if ((fs.f_flags & MNT_RDONLY) && !(system && allow_readonly_root)) return -1;
    if ((fs.f_flags & MNT_NOSUID) || (!system && !(fs.f_flags & MNT_NODEV))) return -1;
    if (volume_uuid(path, actual) || memcmp(actual, expected, 16)) return -1;
    return 0;
}

static int no_root_snapshots(void) {
    int fd = open("/", O_RDONLY); if (fd < 0) return -1;
    struct attrlist attrs; memset(&attrs, 0, sizeof(attrs));
    attrs.bitmapcount = ATTR_BIT_MAP_COUNT; attrs.commonattr = ATTR_CMN_NAME;
    char *buffer = malloc(65536); if (!buffer) { close(fd); return -1; }
    int count = fs_snapshot_list(fd, &attrs, buffer, 65536, 0);
    free(buffer); close(fd); return count == 0 ? 0 : -1;
}

int main(int argc, char **argv) {
    const char *binding = NULL, *identity = NULL;
    if (argc < 2 || (strcmp(argv[1], "verify") && strcmp(argv[1], "start") && strcmp(argv[1], "remount")))
        return failure("usage: verify|start|remount --binding FILE --package FILE");
    for (int i = 2; i < argc; i += 2) {
        if (i + 1 >= argc) return failure("missing option value");
        if (!strcmp(argv[i], "--binding") && !binding) binding = argv[i + 1];
        else if (!strcmp(argv[i], "--package") && !identity) identity = argv[i + 1];
        else return failure("unknown or duplicate option");
    }
    if (!binding || !identity || geteuid() != 0) return failure("root-owned binding/package and root uid required");
    allow_readonly_root = !strcmp(argv[1], "remount");
    struct utsname host;
    if (uname(&host) || strncmp(host.release, "21.6.", 5)) return failure("requires running XNU21.6");
    document d;
    if (load_document(binding, &d)) return failure("invalid root-owned JSON binding");
    char build[16], layout[40], system_text[64], data_text[64], runtime[1024], fingerprint[80], policy[64];
    if (string_value(&d, "build", build, sizeof(build)) || strcmp(build, "19H422") ||
        string_value(&d, "layout", layout, sizeof(layout)) || strcmp(layout, "system-rootful-v1") ||
        string_value(&d, "system_uuid", system_text, sizeof(system_text)) ||
        string_value(&d, "data_uuid", data_text, sizeof(data_text)) ||
        string_value(&d, "runtime_root", runtime, sizeof(runtime)) ||
        string_value(&d, "package_fingerprint", fingerprint, sizeof(fingerprint)) ||
        string_value(&d, "amfi_policy", policy, sizeof(policy)) || strcmp(policy, "palera1n-trustcache-bypass")) {
        free(d.text); return failure("missing or incompatible typed binding fields");
    }
    int system = slice_value(&d, "system_slice"), data = slice_value(&d, "data_slice");
    uint8_t suuid[16], duuid[16];
    if (system < 0 || data < 0 || system == data || normalize_uuid(system_text, suuid) ||
        normalize_uuid(data_text, duuid) || !memcmp(suuid, duuid, 16)) {
        free(d.text); return failure("invalid distinct non-native volume identities");
    }
    char *package = NULL;
    if (read_owned(identity, &package, 256)) { free(d.text); return failure("invalid package identity file"); }
    size_t len = strlen(package); while (len && (package[len - 1] == '\n' || package[len - 1] == '\r')) package[--len] = 0;
    if (len != 64 || strlen(fingerprint) != 64 || strcmp(package, fingerprint)) {
        free(package); free(d.text); return failure("package identity mismatch");
    }
    free(package);
    if (strcmp(runtime, "/")) {
        free(d.text); return failure("rootful runtime root must be /");
    }
    if (check_volume("/", system, suuid, 1) || check_volume("/private/var", data, duuid, 0) ||
        no_root_snapshots()) {
        free(d.text); return failure("runtime UUID/device/mount/snapshot conditions differ from binding");
    }
    /* Update only the checked live root, with the same APFS ABI as pinned
       upstream jbinit loader/remount.c. No snapshot, seal or other mount changes. */
    if (allow_readonly_root) {
        struct statfs fs;
        if (statfs("/", &fs)) { free(d.text); return failure("statfs before root remount"); }
        if (fs.f_flags & MNT_RDONLY) {
            apfs_mount_args_t args;
            memset(&args, 0, sizeof(args));
            args.fspec = fs.f_mntfromname;
            args.mount_mode = APFS_MOUNT_FILESYSTEM;
            if (mount("apfs", "/", MNT_UPDATE, &args)) {
                free(d.text); return failure("actual APFS root RW remount failed");
            }
        }
        allow_readonly_root = 0;
        if (check_volume("/", system, suuid, 1)) {
            free(d.text); return failure("remount did not yield the same writable root");
        }
    }
    free(d.text);
    /* start repeats the actual identity check. Daemon launch/configuration is
       performed explicitly by the rootful job, not hidden in this provider. */
    puts("{\"runtime_identity_verified\":true,\"basic_bootstrap_allowed\":true,\"amfi_policy\":\"palera1n-trustcache-bypass\",\"paleinfo_fd_supplied\":false,\"kernel_rw_supplied\":false,\"dynamic_tc_provider_supplied\":false}");
    return 0;
}
