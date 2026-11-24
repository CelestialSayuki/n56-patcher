#ifndef N56_MACHO_LOADER_H
#define N56_MACHO_LOADER_H

/* Minimal Mach-O definitions needed by the kpf-test host tool. */
#include <stdint.h>

#define MH_MAGIC 0xfeedface
#define MH_CIGAM 0xcefaedfe
#define MH_MAGIC_64 0xfeedfacf
#define MH_CIGAM_64 0xcffaedfe

#define CPU_ARCH_ABI64 0x01000000
#define CPU_TYPE_ARM 12
#define CPU_TYPE_ARM64 (CPU_TYPE_ARM | CPU_ARCH_ABI64)

#define LC_SEGMENT 0x1
#define LC_SYMTAB 0x2
#define LC_UNIXTHREAD 0x5
#define LC_SEGMENT_64 0x19
#define LC_UUID 0x1b

#define VM_PROT_NONE 0
#define VM_PROT_READ 1
#define VM_PROT_WRITE 2
#define VM_PROT_EXECUTE 4

#define SEG_PAGEZERO "__PAGEZERO"
#define SEG_TEXT "__TEXT"

typedef uint32_t cpu_type_t;
typedef uint32_t cpu_subtype_t;
typedef int vm_prot_t;

struct load_command {
    uint32_t cmd;
    uint32_t cmdsize;
};

struct mach_header_64 {
    uint32_t magic;
    cpu_type_t cputype;
    cpu_subtype_t cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
    uint32_t reserved;
};

struct segment_command_64 {
    uint32_t cmd;
    uint32_t cmdsize;
    char segname[16];
    uint64_t vmaddr;
    uint64_t vmsize;
    uint64_t fileoff;
    uint64_t filesize;
    vm_prot_t maxprot;
    vm_prot_t initprot;
    uint32_t nsects;
    uint32_t flags;
};

struct section_64 {
    char sectname[16];
    char segname[16];
    uint64_t addr;
    uint64_t size;
    uint32_t offset;
    uint32_t align;
    uint32_t reloff;
    uint32_t nreloc;
    uint32_t flags;
    uint32_t reserved1;
    uint32_t reserved2;
    uint32_t reserved3;
};

struct thread_command {
    uint32_t cmd;
    uint32_t cmdsize;
};

#define ARM_THREAD_STATE64 6

typedef struct _STRUCT_ARM_THREAD_STATE64 {
    uint64_t __x[29];
    uint64_t __fp;
    uint64_t __lr;
    uint64_t __sp;
    uint64_t __pc;
    uint32_t __cpsr;
    uint32_t __pad0c;
    uint64_t __pad[8];
} _STRUCT_ARM_THREAD_STATE64;

#endif
