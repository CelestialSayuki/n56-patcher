#ifndef N56_MINI_MACH_H
#define N56_MINI_MACH_H

typedef unsigned int mach_port_t;
typedef int kern_return_t;
typedef unsigned int mach_msg_type_number_t;
typedef int integer_t;
typedef unsigned int natural_t;
typedef unsigned long long mach_vm_address_t;
typedef unsigned long long mach_vm_size_t;

#define MACH_PORT_NULL 0
#define KERN_SUCCESS 0

#define TASK_DYLD_INFO 17

#pragma pack(push, 4)
struct task_dyld_info {
    mach_vm_address_t all_image_info_addr;
    mach_vm_size_t all_image_info_size;
    integer_t all_image_info_format;
};
#pragma pack(pop)

typedef struct task_dyld_info task_dyld_info_data_t;
typedef integer_t *task_info_t;
#define TASK_DYLD_INFO_COUNT ((mach_msg_type_number_t)(sizeof(task_dyld_info_data_t) / sizeof(natural_t)))

mach_port_t mach_task_self(void);
mach_port_t mach_host_self(void);
kern_return_t task_for_pid(mach_port_t, int, mach_port_t *);
kern_return_t task_info(mach_port_t, natural_t, task_info_t, mach_msg_type_number_t *);
const char *mach_error_string(kern_return_t);

#endif
