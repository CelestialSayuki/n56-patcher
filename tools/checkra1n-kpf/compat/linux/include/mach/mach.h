#ifndef N56_MACH_MACH_H
#define N56_MACH_MACH_H

/* Minimal Mach types for the Linux host build of checkra1n-kpf. */
#include <stdint.h>

typedef int kern_return_t;
typedef uintptr_t vm_map_t;
typedef uint64_t mach_vm_address_t;
typedef uint64_t mach_vm_size_t;
typedef int boolean_t;
typedef int vm_prot_t;

#define KERN_SUCCESS 0
#define KERN_FAILURE 5
#define KERN_PROTECTION_FAILURE 2
#define KERN_VM_OOM 8

#define VM_PROT_NONE 0
#define VM_PROT_READ 1
#define VM_PROT_WRITE 2
#define VM_PROT_EXECUTE 4

static inline vm_map_t mach_task_self(void) { return 0; }
static inline const char *mach_error_string(kern_return_t kr)
{
    (void)kr;
    return "mach error";
}

#endif
