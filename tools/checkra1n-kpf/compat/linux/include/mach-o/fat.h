#ifndef N56_MACHO_FAT_H
#define N56_MACHO_FAT_H

#include <stdint.h>

#define FAT_MAGIC 0xcafebabe
#define FAT_CIGAM 0xbebafeca

struct fat_header {
    uint32_t magic;
    uint32_t nfat_arch;
};

struct fat_arch {
    uint32_t cputype;
    uint32_t cpusubtype;
    uint32_t offset;
    uint32_t size;
    uint32_t align;
};

#endif
