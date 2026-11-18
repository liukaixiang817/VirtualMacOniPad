// Read-only metadata probe for native, per-extension approval interfaces.
#import <Foundation/Foundation.h>
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <mach-o/getsect.h>
#include <objc/runtime.h>
static NSArray *methods(Class cls) {
    NSMutableArray *rows = [NSMutableArray array];
    unsigned count = 0; Method *items = class_copyMethodList(cls, &count);
    for (unsigned i = 0; i < count; ++i)
        [rows addObject:@{@"selector":@(sel_getName(method_getName(items[i]))),
                         @"encoding":@(method_getTypeEncoding(items[i]))}];
    free(items); return rows;
}
int main(void) { @autoreleasepool {
    NSString *path = @"/System/Library/PrivateFrameworks/SystemPolicy.framework/SystemPolicy";
    void *module = dlopen(path.fileSystemRepresentation, RTLD_NOW | RTLD_LOCAL);
    if (!module) { fprintf(stderr, "%s\n", dlerror()); return 69; }
    NSMutableArray *strings = [NSMutableArray array];
    for (uint32_t i = 0; i < _dyld_image_count(); ++i) {
        NSString *loaded = @(_dyld_get_image_name(i));
        if ([loaded hasSuffix:@"/SystemPolicy"]) {
            path = loaded;
            const struct mach_header_64 *header = (const void *)_dyld_get_image_header(i);
            const struct section_64 *section = getsectbynamefromheader_64(header, "__TEXT", "__cstring");
            if (section && section->size <= 2 * 1024 * 1024) {
                const char *start = (const void *)(section->addr + _dyld_get_image_vmaddr_slide(i));
                size_t cursor = 0;
                while (cursor < section->size) {
                    const char *end = memchr(start + cursor, 0, section->size - cursor);
                    if (!end) break;
                    NSString *value = [[NSString alloc] initWithBytes:start + cursor length:end - start - cursor encoding:NSUTF8StringEncoding];
                    if (value && ([value containsString:@"uthoriz"] || [value containsString:@"com.apple."] || [value containsString:@"UAKL"])) [strings addObject:value];
                    cursor = end - start + 1;
                }
            }
            break;
        }
    }
    unsigned count = 0;
    const char **names = objc_copyClassNamesForImage(path.UTF8String, &count);
    NSMutableArray *rows = [NSMutableArray array];
    for (unsigned i = 0; i < count; ++i) {
        NSString *name = @(names[i]);
        if ([name rangeOfString:@"Kext" options:NSCaseInsensitiveSearch].location == NSNotFound &&
            [name rangeOfString:@"Kernel" options:NSCaseInsensitiveSearch].location == NSNotFound) continue;
        Class cls = objc_getClass(names[i]);
        [rows addObject:@{@"class":name, @"classMethods":methods(object_getClass(cls)),
                         @"instanceMethods":methods(cls)}];
    }
    free(names);
    NSData *data = [NSJSONSerialization dataWithJSONObject:@{@"schema":@1, @"image":path,
        @"classCount":@(count), @"classes":rows, @"approvalRelatedStrings":strings, @"policyMutation":@NO}
        options:NSJSONWritingPrettyPrinted | NSJSONWritingSortedKeys error:NULL];
    if (!data) return 70;
    fwrite(data.bytes, 1, data.length, stdout); fputc('\n', stdout);
    return 0;
} }
