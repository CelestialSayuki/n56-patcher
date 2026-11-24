#ifndef N56_MINI_HOST_SPECIAL_PORTS_H
#define N56_MINI_HOST_SPECIAL_PORTS_H

#define HOST_LOCAL_NODE -1

kern_return_t host_get_special_port(mach_port_t, int, int, mach_port_t *);

#endif
