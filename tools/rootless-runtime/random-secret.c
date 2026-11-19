/* Native getentropy only; output consumed privately by the rootful passwd tool. */
#include <stdio.h>
#include <stddef.h>
/* Stable iOS libSystem ABI; host CLT headers hide this iOS declaration. */
extern int getentropy(void *, size_t);
int main(void) {
    unsigned char bytes[32];
    if (getentropy(bytes, sizeof(bytes))) return 1;
    for (unsigned i=0; i<sizeof(bytes); ++i) if (printf("%02x", bytes[i]) < 0) return 1;
    return puts("") < 0;
}
