#import "vm27_display_services_unavailable_v1.h"
#import <objc/message.h>
#import <objc/runtime.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    unsigned tests = 0, failures = 0, caught = 0;
#define CHECK(x) do { ++tests; if (!(x)) ++failures; } while (0)
    __weak id weakObject;
    @autoreleasepool {
        VM27DSClientV1 *object = [VM27DSClientV1 new];
        weakObject = object;
        CHECK(object != nil);
        CHECK(!strcmp(class_getName(object_getClass(object)), "VM27DSClientV1"));
        CHECK([object isKindOfClass:[NSObject class]]);
        CHECK(![object respondsToSelector:NSSelectorFromString(@"vm27UnavailableDisplayQuery:")]);
        CHECK(objc_getClass("DisplayServicesClient") != object_getClass(object));
        @try {
            ((void (*)(id, SEL, id))objc_msgSend)(object,
                NSSelectorFromString(@"vm27UnavailableDisplayQuery:"), @"actual query");
            CHECK(0);
        } @catch (NSException *exception) {
            ++caught;
            CHECK([exception.name isEqualToString:@"VM27UnavailableDisplayServices"]);
            CHECK([exception.reason containsString:@"vm27UnavailableDisplayQuery:"]);
        }
    }
    CHECK(weakObject == nil);
    int actualRequirement = 7;
    CHECK(VM27PluginUnavailableV1("/actual/plugin.bundle", 2, &actualRequirement) == ENOTSUP);
    CHECK(VM27PluginUnavailableV1(NULL, 2, &actualRequirement) == EINVAL);
    CHECK(VM27PluginUnavailableV1("", 2, &actualRequirement) == EINVAL);
    CHECK(VM27PluginUnavailableV1("/actual/plugin.bundle", 0, &actualRequirement) == EINVAL);
    CHECK(VM27PluginUnavailableV1("/actual/plugin.bundle", 2, NULL) == EINVAL);
    @autoreleasepool {
        for (unsigned n = 0; n != 2; ++n) {
            @try {
                if (n == 0) (void)VM27CGUnavailableV1(UINT32_MAX);
                else (void)VM27HeadroomUnavailableV1(1);
                CHECK(0);
            } @catch (NSException *exception) {
                ++caught;
                CHECK([exception.name isEqualToString:@"VM27UnsupportedMacDisplayProfile"]);
                CHECK([exception.reason containsString:n == 0 ? @"CGDisplayCopyColorSpace"
                                                            : @"SLSDisplayGetPotentialHeadroom"]);
            }
        }
    }
    printf("{\"tests\":%u,\"failures\":%u,\"caughtUnavailable\":%u,\"fakeAppleClass\":false}\n",
           tests, failures, caught);
    return failures ? 1 : 0;
}
