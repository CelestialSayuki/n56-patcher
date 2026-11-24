/* Stubs for pongoOS host services that the offline kpf-test tool never uses. */
#include <stddef.h>
#include <stdint.h>

void queue_rx_string(const char *s) { (void)s; }
void *loader_xfer_recv_data;
uint32_t loader_xfer_recv_count;
size_t autoboot_count;
volatile char gBootFlag;
void task_yield(void) {}
void *gDeviceTree;
int socnum;
void dt_parse(void *a, uint32_t b) { (void)a; (void)b; }
void *dt_prop(void *a, const char *b, size_t *c)
{
    (void)a; (void)b; (void)c;
    return NULL;
}
void *dt_find(void *a, const char *b)
{
    (void)a; (void)b;
    return NULL;
}
void *dt_alloc_memmap(void *a)
{
    (void)a;
    return NULL;
}
void *dt_get_prop(void *a, const char *b, size_t *c)
{
    (void)a; (void)b; (void)c;
    return NULL;
}
