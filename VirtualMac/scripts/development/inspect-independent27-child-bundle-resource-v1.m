#import <Foundation/Foundation.h>
#include <stdio.h>

/* HOST read-only resource lookup. No load, dlopen, spawn or sandbox call. */
int main(int argc, const char *argv[]) {
    @autoreleasepool {
        if (argc != 2) return 2;
        NSString *path = [[NSString stringWithUTF8String:argv[1]] stringByResolvingSymlinksInPath];
        NSBundle *bundle = [NSBundle bundleWithPath:path];
        if (!bundle) return 3;
        NSString *resource = [bundle pathForResource:@"com.apple.Virtualization.VirtualMachine" ofType:@"sb"];
        NSDictionary *result = @{
            @"actualBundlePath": bundle.bundlePath ?: (id)[NSNull null],
            @"actualResourcePath": bundle.resourcePath ?: (id)[NSNull null],
            @"actualExecutablePath": bundle.executablePath ?: (id)[NSNull null],
            @"actualPackageType": [bundle objectForInfoDictionaryKey:@"CFBundlePackageType"] ?: (id)[NSNull null],
            @"actualSandboxProfileLookup": resource ?: (id)[NSNull null],
            @"bundleLoaded": @(bundle.isLoaded),
            @"sandboxInitializationExecuted": @NO,
            @"hostOnly": @YES
        };
        NSError *error = nil;
        NSData *data = [NSJSONSerialization dataWithJSONObject:result options:NSJSONWritingPrettyPrinted error:&error];
        if (!data || error || bundle.isLoaded) return 4;
        if (fwrite(data.bytes, 1, data.length, stdout) != data.length) return 5;
        if (fputc('\n', stdout) == EOF) return 5;
        return 0;
    }
}
