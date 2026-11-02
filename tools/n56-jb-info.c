#include <mach/mach.h>
#include <mach/host_special_ports.h>
#include <stdio.h>

int main(void)
{
    mach_port_t task = MACH_PORT_NULL;
    kern_return_t kr = task_for_pid(mach_task_self(), 0, &task);
    printf("task_for_pid(0): %s\n", mach_error_string(kr));
    if (kr != KERN_SUCCESS) {
        kr = host_get_special_port(mach_host_self(), HOST_LOCAL_NODE, 4, &task);
        printf("host special port 4: %s, port=%u\n", mach_error_string(kr), task);
    }
    if (kr != KERN_SUCCESS || task == MACH_PORT_NULL) return 1;
    task_dyld_info_data_t info = {0};
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    kr = task_info(task, TASK_DYLD_INFO, (task_info_t)&info, &count);
    printf("TASK_DYLD_INFO: %s, address=0x%llx, size=0x%llx\n",
           mach_error_string(kr), info.all_image_info_addr, info.all_image_info_size);
    return kr == KERN_SUCCESS ? 0 : 1;
}
