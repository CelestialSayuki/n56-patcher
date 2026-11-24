#ifndef N56_MINI_COREFOUNDATION_H
#define N56_MINI_COREFOUNDATION_H

/* Enough of CoreFoundation for the small helpers deployed into the SSH
   ramdisk. The real framework is loaded from the device's dyld shared cache;
   this header and the matching libCoreFoundation.tbd only let Linux clang/ld64
   produce the right Mach-O bindings. */
typedef unsigned char Boolean;
typedef long CFIndex;
typedef unsigned long CFTypeID;
typedef unsigned int CFStringEncoding;

typedef const void *CFTypeRef;
typedef const struct __CFString *CFStringRef;
typedef const struct __CFAllocator *CFAllocatorRef;

#define kCFStringEncodingUTF8 0x08000100U

CFStringRef CFStringCreateWithCString(CFAllocatorRef allocator, const char *string,
                                      CFStringEncoding encoding);
Boolean CFStringGetCString(CFStringRef string, char *buffer, CFIndex bufferSize,
                           CFStringEncoding encoding);
CFTypeID CFGetTypeID(CFTypeRef object);
CFTypeID CFStringGetTypeID(void);
void CFRelease(CFTypeRef object);

#endif
