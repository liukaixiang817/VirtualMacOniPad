#include <CoreFoundation/CoreFoundation.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern const CFStringRef VM27RequestTerminateFixtureKey;
static unsigned checks;
static void require(int value) {
    ++checks;
    if (!value) abort();
}

int main(void) {
    // The native framework is an ordinary link dependency. NOLOAD proves the
    // comparison obtains its already loaded genuine definition.
    void *owner = dlopen("/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit",
                        RTLD_NOW | RTLD_NOLOAD);
    require(owner != NULL);
    const CFStringRef *native = dlsym(owner, "kIOHIDServiceRequestTerminateKey");
    require(native != NULL && *native != NULL);
    CFStringRef actual = VM27RequestTerminateFixtureKey;
    require(actual != NULL && CFGetTypeID(actual) == CFStringGetTypeID());
    require(CFGetTypeID(*native) == CFStringGetTypeID());
    require(CFEqual(actual, *native));
    require(CFStringGetLength(actual) == 16 && CFStringGetLength(*native) == 16);
    char encoded[32] = {0};
    require(CFStringGetCString(actual, encoded, sizeof(encoded), kCFStringEncodingUTF8));
    require(!strcmp(encoded, "RequestTerminate"));
    unsigned lifetime = 0;
    for (unsigned i = 0; i < 256; ++i) {
        CFTypeRef retained = CFRetain(actual);
        require(retained == actual && CFEqual(retained, *native));
        CFRelease(retained);
        require(VM27RequestTerminateFixtureKey == actual && CFGetTypeID(actual) == CFStringGetTypeID());
        ++lifetime;
    }
    const void *keys[] = {*native};
    const void *values[] = {CFSTR("owned value")};
    CFDictionaryRef dictionary = CFDictionaryCreate(NULL, keys, values, 1,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    require(dictionary != NULL);
    require(CFDictionaryGetValue(dictionary, actual) == values[0]);
    require(CFDictionaryGetValue(dictionary, CFSTR("RequestTerminated")) == NULL);
    CFRelease(dictionary);
    require(CFStringCompare(actual, *native, 0) == kCFCompareEqualTo);
    require(!CFEqual(actual, CFSTR("requestTerminate")));
    require(!CFEqual(actual, CFSTR("RequestTerminateKey")));
    printf("{\"checks\":%u,\"nativeIOKitConstantCompared\":true,\"retainReleasePairs\":%u,"
           "\"actualType\":\"CFString\",\"characters\":16,\"value\":\"RequestTerminate\","
           "\"nativeHIDEventConstructorsExecuted\":false}\n", checks, lifetime);
    require(dlclose(owner) == 0);
    return 0;
}
