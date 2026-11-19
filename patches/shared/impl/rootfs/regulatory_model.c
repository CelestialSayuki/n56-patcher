#include <CoreFoundation/CoreFoundation.h>
#include <dlfcn.h>
#include <stdio.h>

int main(void) {
    void *library = dlopen("/usr/lib/libMobileGestalt.dylib", RTLD_LAZY);
    CFTypeRef (*copy_answer)(CFStringRef) = library ? dlsym(library, "MGCopyAnswer") : NULL;
    if (!copy_answer) {
        fprintf(stderr, "MobileGestalt unavailable\n");
        return 1;
    }
    CFTypeRef answer = copy_answer(CFSTR("RegulatoryModelNumber"));
    char model[64];
    if (!answer || CFGetTypeID(answer) != CFStringGetTypeID() ||
        !CFStringGetCString(answer, model, sizeof(model), kCFStringEncodingUTF8)) {
        fprintf(stderr, "RegulatoryModelNumber unavailable\n");
        if (answer) CFRelease(answer);
        return 1;
    }
    puts(model);
    CFRelease(answer);
    return 0;
}
