/* Synthetic HOST file only; no device is opened. */
#include <assert.h>
#include <stdio.h>
#include "../include/paleinfo-user.h"
int main(void) {
    FILE *f = tmpfile(); assert(f);
    uint32_t offset = 128;
    assert(fwrite(&offset, 4, 1, f) == 1);
    assert(fseek(f, offset, SEEK_SET) == 0);
    struct paleinfo expected = { .magic = PALEINFO_MAGIC, .version = 2,
        .kbase = UINT64_C(0xfffffff007008000), .kslide = 0x4000, .flags = 0x82,
        .rootdev = "disk0s1s8" };
    assert(fwrite(&expected, sizeof(expected), 1, f) == 1); fflush(f);
    struct paleinfo actual;
    assert(n56_paleinfo_read_fd(fileno(f), &actual) == 0);
    assert(memcmp(&actual, &expected, sizeof(actual)) == 0);
    actual.version = 1;
    assert(n56_paleinfo_validate(&actual) == -1 && errno == EINVAL);
    fclose(f);
    puts("paleinfo v2 synthetic FD ABI: OK (native host, no device)");
    return 0;
}
