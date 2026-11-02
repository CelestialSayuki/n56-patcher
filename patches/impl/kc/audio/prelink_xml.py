"""Use IOKit's XML reader to validate the kext catalogue format."""
import ctypes


def validate(raw):
    iokit = ctypes.CDLL('/System/Library/Frameworks/IOKit.framework/IOKit')
    foundation = ctypes.CDLL('/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation')
    parse = iokit.IOCFUnserialize
    parse.argtypes = [ctypes.c_char_p, ctypes.c_void_p, ctypes.c_ulong,
                      ctypes.POINTER(ctypes.c_void_p)]
    parse.restype = ctypes.c_void_p
    foundation.CFRelease.argtypes = [ctypes.c_void_p]
    foundation.CFStringGetCString.argtypes = [ctypes.c_void_p, ctypes.c_char_p,
                                             ctypes.c_long, ctypes.c_uint32]
    foundation.CFStringGetCString.restype = ctypes.c_bool
    error = ctypes.c_void_p()
    result = parse(raw, None, 0, ctypes.byref(error))
    if result:
        foundation.CFRelease(result)
        return
    message = 'IOKit rejected the prelink catalogue'
    if error.value:
        text = ctypes.create_string_buffer(1024)
        foundation.CFStringGetCString(error, text, len(text), 0x08000100)
        message = text.value.decode()
        foundation.CFRelease(error)
    raise ValueError(message)
