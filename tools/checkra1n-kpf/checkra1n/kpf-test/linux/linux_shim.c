/* Linux host shim for the checkra1n KPF host tool. */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

void panic(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fputs("KPF panic: ", stderr);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
    abort();
}
