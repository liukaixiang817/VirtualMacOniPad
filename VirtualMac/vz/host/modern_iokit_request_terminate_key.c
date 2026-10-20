// The genuine macOS27 export is an immutable process-lifetime CFStringRef,
// not a char pointer. Its cache object contains the 16-byte RequestTerminate
// literal. The two original UH callers bridge its value to Swift String.
#include <CoreFoundation/CoreFoundation.h>

#ifndef VM27_REQUEST_TERMINATE_SYMBOL
#define VM27_REQUEST_TERMINATE_SYMBOL kIOHIDServiceRequestTerminateKey
#endif

__attribute__((visibility("default")))
const CFStringRef VM27_REQUEST_TERMINATE_SYMBOL = CFSTR("RequestTerminate");
