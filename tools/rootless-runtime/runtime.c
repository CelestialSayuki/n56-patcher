/* System15 basic-rootless runtime identity guard. No kernel-RW or fake paleinfo. */
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
#include <syslog.h>
#include <sys/utsname.h>
#include <unistd.h>
#define JSMN_STATIC
#define JSMN_PARENT_LINKS
#include "jsmn.h"
#include "apfs_mount_args.h"

typedef struct { char *text; jsmntok_t tokens[256]; int count; } document;

static int failure(const char *message) {
    int saved = errno;
    fprintf(stderr, "n56 rootless runtime: %s (errno=%d)\n", message, saved);
    openlog("n56-rootless-bootstrap", LOG_CONS | LOG_PID, LOG_DAEMON);
    syslog(LOG_ERR, "%s (errno=%d)", message, saved);
    closelog();
    errno = saved;
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

static int reject_volume(char *error, size_t capacity, const char *path, const char *reason, int code) {
    snprintf(error, capacity, "%s: %s", path, reason);
    errno = code;
    return -1;
}

/* APFS update mounts need the filesystem-specific argument struct; the generic
   `/sbin/mount -u -o suid` path returns EPERM because it supplies no apfs args.
   Clear nosuid on the Data volume the way palera1n does: a direct mount(2)
   MNT_UPDATE with apfs_mount_args. rw + nodev + suid + exec, matching binding. */
static int remount_data_suid(int slice) {
    struct statfs fs;
    if (statfs("/private/var", &fs)) return -1;
    if (!(fs.f_flags & MNT_NOSUID)) return 0; /* already suid */
    char device[64];
    snprintf(device, sizeof(device), "/dev/disk0s1s%d", slice);
    struct apfs_mount_args args;
    memset(&args, 0, sizeof(args));
    args.fspec = device;
    args.apfs_flags = (uint64_t)(MNT_UPDATE | MNT_NODEV);
    args.mount_mode = APFS_MOUNT_FILESYSTEM;
    return mount("apfs", "/private/var", MNT_UPDATE | MNT_NODEV, &args);
}

static int check_volume(const char *path, int slice, const uint8_t expected[16], int system,
                        int require_suid, char *error, size_t capacity) {
    struct statfs fs; uint8_t actual[16]; char device[64];
    snprintf(device, sizeof(device), "/dev/disk0s1s%d", slice);
    if (statfs(path, &fs)) {
        int saved = errno;
        snprintf(error, capacity, "%s: statfs failed", path);
        errno = saved;
        return -1;
    }
    if (strcmp(fs.f_fstypename, "apfs"))
        return reject_volume(error, capacity, path, "not mounted as APFS", EINVAL);
    if (strcmp(fs.f_mntfromname, device) || strcmp(fs.f_mntonname, system ? "/" : "/private/var"))
        return reject_volume(error, capacity, path, "device or mountpoint differs from binding", EINVAL);
    if (system && !(fs.f_flags & MNT_RDONLY))
        return reject_volume(error, capacity, path, "System mount is not read-only", EPERM);
    if (!system && (fs.f_flags & MNT_RDONLY))
        return reject_volume(error, capacity, path, "Data mount is read-only", EPERM);
    if (!system && require_suid && (fs.f_flags & MNT_NOSUID))
        return reject_volume(error, capacity, path,
                             "Data still nosuid after runtime remount", EPERM);
    if (!system && !(fs.f_flags & MNT_NODEV))
        return reject_volume(error, capacity, path, "Data mount lost nodev", EPERM);
    if (volume_uuid(path, actual) || memcmp(actual, expected, 16))
        return reject_volume(error, capacity, path, "volume UUID differs from binding", EINVAL);
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
    if (argc < 2 || (strcmp(argv[1], "verify") && strcmp(argv[1], "start")))
        return failure("usage: verify|start --binding FILE --package FILE");
    for (int i = 2; i < argc; i += 2) {
        if (i + 1 >= argc) return failure("missing option value");
        if (!strcmp(argv[i], "--binding") && !binding) binding = argv[i + 1];
        else if (!strcmp(argv[i], "--package") && !identity) identity = argv[i + 1];
        else return failure("unknown or duplicate option");
    }
    if (!binding || !identity || geteuid() != 0) return failure("root-owned binding/package and root uid required");
    struct utsname host;
    if (uname(&host) || strncmp(host.release, "21.6.", 5)) return failure("requires running XNU21.6");
    document d;
    if (load_document(binding, &d)) return failure("invalid root-owned JSON binding");
    char build[16], layout[40], system_text[64], data_text[64], runtime[1024], fingerprint[80], policy[64];
    if (string_value(&d, "build", build, sizeof(build)) || strcmp(build, "19H422") ||
        string_value(&d, "layout", layout, sizeof(layout)) || strcmp(layout, "data-private-preboot-v1") ||
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
    char resolved[1024];
    ssize_t target_length = readlink("/var/jb", resolved, sizeof(resolved) - 1);
    if (target_length < 0 || target_length >= (ssize_t)sizeof(resolved) - 1) {
        free(d.text); return failure("missing or oversized /var/jb target");
    }
    resolved[target_length] = 0;
    if (strncmp(runtime, "/private/var/", 13) || strcmp(runtime, resolved)) {
        free(d.text); return failure("foreign /var/jb target");
    }
    int is_start = !strcmp(argv[1], "start");
    if (is_start && remount_data_suid(data))
        fprintf(stderr, "n56 rootless runtime: Data suid remount failed (errno=%d)\n", errno);
    char volume_error[192];
    if (check_volume("/", system, suuid, 1, 0, volume_error, sizeof(volume_error))) {
        free(d.text); return failure(volume_error);
    }
    if (check_volume("/private/var", data, duuid, 0, is_start, volume_error, sizeof(volume_error))) {
        free(d.text); return failure(volume_error);
    }
    if (check_volume(runtime, data, duuid, 0, is_start, volume_error, sizeof(volume_error))) {
        free(d.text); return failure(volume_error);
    }
    if (no_root_snapshots()) {
        free(d.text); return failure("root snapshot list is non-empty or unreadable");
    }
    free(d.text);
    /* start repeats the actual identity check. Daemon launch/configuration is
       performed explicitly by the rootless job, not hidden in this provider. */
    puts("{\"runtime_identity_verified\":true,\"basic_bootstrap_allowed\":true,\"amfi_policy\":\"palera1n-trustcache-bypass\",\"paleinfo_fd_supplied\":false,\"kernel_rw_supplied\":false,\"dynamic_tc_provider_supplied\":false}");
    return 0;
}
