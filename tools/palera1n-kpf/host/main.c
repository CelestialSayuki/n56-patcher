/*
 * Native offline adapter for palera1n/PongoOS e98323f8.
 * Maps ARM64 Mach-O segments as RW DATA, invokes only compiled host C, exports
 * file-backed segments, and writes machine-readable patch/SSV/cave evidence.
 * No USB, SSH, DeviceTree installation, JIT, or executable ARM mappings.
 * The mapped-host API follows PongoOS's MIT-licensed kpf-test (see vendor).
 */
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#define sleep pongo_sleep
#define usleep pongo_usleep
#include "kpf.h"
#undef sleep
#undef usleep
#include "offline.h"

extern void module_entry(void);
extern uint32_t offsetof_p_flags;
extern void (*preboot_hook)(void);
extern struct mach_header_64 *xnu_header_cached;
void *gEntryPoint;
boot_args *gBootArgs;
void *ramdisk_buf;
uint32_t ramdisk_size;
static boot_args args;
static FILE *events;
static struct mach_header_64 *original;
static uint8_t *memory;
static uint64_t lowest, memory_size;
static size_t file_size;
static const char *cave_file;
static uint64_t cave_va, cave_size;

static void quote(FILE *f, const char *s) {
    fputc('"', f);
    for (; *s; ++s) {
        unsigned char c = *s;
        if (c == '"' || c == '\\') fprintf(f, "\\%c", c);
        else if (c < 32) fprintf(f, "\\u%04x", c);
        else fputc(c, f);
    }
    fputc('"', f);
}

void realpanic(const char *format, ...) {
    va_list ap;
    va_start(ap, format);
    char *text = NULL;
    vasprintf(&text, format, ap);
    va_end(ap);
    fprintf(stderr, "[palera1n KPF panic] %s\n", text ? text : format);
    if (events) {
        fputs("{\"type\":\"panic\",\"message\":", events);
        quote(events, text ? text : format);
        fputs("}\n", events);
        fflush(events);
    }
    exit(3);
}

uint64_t get_ticks(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 24000000 + (uint64_t)t.tv_nsec * 24 / 1000;
}
void command_register(const char *n, const char *d, void (*cb)(const char *, char *)) {
    (void)n; (void)d; (void)cb;
}
void *alloc_static(uint32_t size) { return calloc(1, size); }
void sep_setup(void) {}
void invalidate_icache(void) { realpanic("offline host must never invalidate executable ARM code"); }
void *jit_alloc(size_t n, size_t size) { (void)n; (void)size; realpanic("ARM JIT prohibited"); return NULL; }
void jit_free(void *p) { (void)p; realpanic("ARM JIT prohibited"); }

void n56_audit_match(xnu_pf_patch_t *patch, void *stream) {
    fputs("{\"type\":\"match\",\"name\":", events);
    quote(events, patch->name ? patch->name : "ptr_to_data");
    fprintf(events, ",\"address\":\"0x%016" PRIx64 "\"}\n", xnu_ptr_to_va(stream));
}
void n56_audit_result(xnu_pf_patch_t *patch) {
    fputs("{\"type\":\"patch\",\"name\":", events);
    quote(events, patch->name ? patch->name : "ptr_to_data");
    fprintf(events, ",\"required\":%s,\"found\":%s}\n",
            patch->is_required ? "true" : "false", patch->has_fired ? "true" : "false");
}
void n56_audit_policy(bool ssv, bool livefs, bool arv) {
    fprintf(events, "{\"type\":\"policy\",\"ssv_required\":%s,\"livefs_marker\":%s,\"optional_arv\":%s,"
            "\"apfs_patch_rename\":\"%s\",\"livefs_patch\":false,\"root_remount_rw_patch\":%s,"
            "\"apfs_vfsop_mount\":\"%s\"}\n",
            ssv ? "true" : "false", livefs ? "true" : "false", arv ? "true" : "false",
            ssv ? "skipped_by_upstream_ssv" : "registered_required",
            (palera1n_flags & palerain_option_rootful) ? "true" : "false",
            (palera1n_flags & palerain_option_rootful) ? "required_by_rootful_flag" : "skipped_by_rootless_policy");
    if (arv) realpanic("optional ARV requires explicit DeviceTree policy, unsupported by XNU21 profile");
    if (!ssv) realpanic("XNU21 SSV profile: expected upstream SSV detection");
}
void n56_audit_finish(void) {
    fprintf(events, "{\"type\":\"finish\",\"darwin\":%u,\"darwin_minor\":%u,\"xnu\":%u,"
            "\"platform\":%u,\"flags\":\"0x%016" PRIx64 "\",\"kbase\":\"0x%016" PRIx64 "\","
            "\"kslide\":\"0x%016" PRIx64 "\",\"p_flags_offset\":%u,\"bootargs\":",
            gKernelVersion.darwinMajor, gKernelVersion.darwinMinor, gKernelVersion.xnuMajor,
            xnu_platform(), palera1n_flags, xnu_ptr_to_va(xnu_header()), xnu_slide_value(xnu_header()), offsetof_p_flags);
    quote(events, gBootArgs->iOS13.CommandLine);
    fputs(",\"all_main_invariants_passed\":true}\n", events);
    fflush(events);
}

static struct load_command *command_at(size_t offset) {
    if (offset > file_size || file_size - offset < sizeof(struct load_command))
        realpanic("raw Mach-O command exceeds file");
    struct load_command *lc = (void *)((uint8_t *)original + offset);
    if (lc->cmdsize < 8 || lc->cmdsize > file_size - offset ||
        offset + lc->cmdsize > sizeof(*original) + original->sizeofcmds)
        realpanic("invalid raw Mach-O command");
    return lc;
}

uint32_t *n56_select_shellcode(uint32_t count) {
    if (cave_va) realpanic("shellcode allocator invoked twice");
    uint64_t need = (uint64_t)count * 4;
    FILE *f = fopen(cave_file, "rb");
    if (!f) realpanic("open protected caves: %s", strerror(errno));
    uint64_t pair[2];
    while (fread(pair, sizeof(pair), 1, f) == 1) {
        uint64_t start = pair[0], length = pair[1];
        if (length < need || (start & 15) || start < lowest ||
            start - lowest > memory_size || need > memory_size - (start - lowest)) continue;
        /* Only file-backed executable segment padding. Python excludes every
         * stock/current kext, kernel section, slide slot, and prior declaration. */
        size_t off = sizeof(*original);
        for (uint32_t i = 0; i < original->ncmds; ++i) {
            struct load_command *lc = command_at(off);
            off += lc->cmdsize;
            if (lc->cmd != LC_SEGMENT_64) continue;
            struct segment_command_64 *s = (void *)lc;
            if (!(s->initprot & VM_PROT_EXECUTE) || start < s->vmaddr ||
                start - s->vmaddr > s->filesize || need > s->filesize - (start - s->vmaddr)) continue;
            uint8_t *raw = (uint8_t *)original + s->fileoff + (start - s->vmaddr);
            uint8_t *mapped = memory + (start - lowest);
            bool clean = true;
            for (uint64_t j = 0; j < need; ++j) if (raw[j] || mapped[j]) { clean = false; break; }
            if (!clean) continue;
            cave_va = start; cave_size = need;
            fprintf(events, "{\"type\":\"cave\",\"name\":\"shellcode_area\",\"required\":true,\"found\":true,"
                    "\"address\":\"0x%016" PRIx64 "\",\"size\":%" PRIu64 "}\n", start, need);
            fclose(f);
            return (void *)mapped;
        }
    }
    if (ferror(f)) realpanic("read protected caves failed");
    fclose(f);
    realpanic("Missing patch: shellcode_area (need 0x%" PRIx64 " protected executable bytes)", need);
    return NULL;
}

int main(int argc, char **argv) {
    if (argc != 5 && argc != 6) {
        fprintf(stderr, "usage: %s stock.raw output.raw events.jsonl caves.bin [rootless|rootful]\n", argv[0]);
        return 2;
    }
    bool rootful = argc == 6 && !strcmp(argv[5], "rootful");
    if (argc == 6 && !rootful && strcmp(argv[5], "rootless")) {
        fprintf(stderr, "invalid jailbreak layout\n"); return 2;
    }
    setvbuf(stdout, NULL, _IOLBF, 0);
    cave_file = argv[4];
    events = fopen(argv[3], "w");
    if (!events) { perror(argv[3]); return 2; }
    setvbuf(events, NULL, _IOLBF, 0);
    int fd = open(argv[1], O_RDONLY);
    struct stat st;
    if (fd < 0 || fstat(fd, &st) || st.st_size < sizeof(*original)) realpanic("open stock raw failed");
    file_size = st.st_size;
    original = mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (original == MAP_FAILED) realpanic("mmap stock failed");
    if (original->magic != MH_MAGIC_64 || original->cputype != CPU_TYPE_ARM64 ||
        original->filetype != MH_EXECUTE || original->sizeofcmds > file_size - sizeof(*original))
        realpanic("requires thin, uncompressed ARM64 MH_EXECUTE KC");
    uint64_t highest = 0, entry = 0, header_va = 0;
    lowest = UINT64_MAX;
    size_t off = sizeof(*original);
    for (uint32_t i = 0; i < original->ncmds; ++i) {
        struct load_command *lc = command_at(off);
        off += lc->cmdsize;
        if (lc->cmd == LC_SEGMENT_64) {
            if (lc->cmdsize < sizeof(struct segment_command_64)) realpanic("short segment");
            struct segment_command_64 *s = (void *)lc;
            if (s->filesize > s->vmsize || s->fileoff > file_size || s->filesize > file_size - s->fileoff ||
                s->vmaddr + s->vmsize < s->vmaddr) realpanic("bad segment extent");
            if (s->fileoff == 0 && s->filesize >= sizeof(*original)) header_va = s->vmaddr;
            if (s->vmsize) {
                if (s->vmaddr < lowest) lowest = s->vmaddr;
                if (s->vmaddr + s->vmsize > highest) highest = s->vmaddr + s->vmsize;
            }
        } else if (lc->cmd == LC_UNIXTHREAD) {
            if (lc->cmdsize < 16 + 33 * 8 || *(uint32_t *)((uint8_t *)lc + 8) != 6)
                realpanic("bad ARM64 thread state");
            memcpy(&entry, (uint8_t *)lc + 16 + 32 * 8, 8);
        }
    }
    if (off != sizeof(*original) + original->sizeofcmds || lowest == UINT64_MAX ||
        highest < lowest || highest - lowest > 512ULL * 1024 * 1024 || entry < lowest || entry >= highest)
        realpanic("unsupported raw memory layout");
    memory_size = highest - lowest;
    memory = mmap(NULL, memory_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (memory == MAP_FAILED) realpanic("mmap data-only kernel memory failed");
    off = sizeof(*original);
    for (uint32_t i = 0; i < original->ncmds; ++i) {
        struct load_command *lc = command_at(off); off += lc->cmdsize;
        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *s = (void *)lc;
            memcpy(memory + s->vmaddr - lowest, (uint8_t *)original + s->fileoff, s->filesize);
        }
    }
    args.Revision = 0x1337; args.Version = 0x1469;
    args.virtBase = lowest; args.physBase = (uint64_t)memory;
    args.memSize = memory_size; args.topOfKernelData = (uint64_t)memory + memory_size;
    gBootArgs = &args; gEntryPoint = memory + entry - lowest;
    /* Explicit cached header avoids the device entry-point page scan on host. */
    if (header_va < lowest || header_va >= highest) realpanic("missing file-backed main header");
    xnu_header_cached = (void *)(memory + header_va - lowest);
    if (xnu_header_cached->magic != MH_MAGIC_64) realpanic("mapped main header mismatch");
    palera1n_flags = rootful ? palerain_option_rootful : palerain_option_rootless;
    module_entry();
    if (!preboot_hook) realpanic("missing KPF preboot entry");
    preboot_hook();
    uint8_t *image = malloc(file_size);
    if (!image) realpanic("output allocation failed");
    memcpy(image, original, file_size);
    off = sizeof(*original);
    for (uint32_t i = 0; i < original->ncmds; ++i) {
        struct load_command *lc = command_at(off); off += lc->cmdsize;
        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *s = (void *)lc;
            memcpy(image + s->fileoff, memory + s->vmaddr - lowest, s->filesize);
        }
    }
    FILE *out = fopen(argv[2], "wb");
    if (!out || fwrite(image, 1, file_size, out) != file_size || fclose(out)) realpanic("export raw failed");
    free(image); fclose(events);
    printf("Exported data-only patched KC: %s\n", argv[2]);
    return 0;
}
