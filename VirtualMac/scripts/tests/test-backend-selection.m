#import "../../vz/host/VZBackendSelection.h"
#import "../../vz/host/VZAppSettings.h"
#include "../../vz/host/VZFrameworkIdentity.h"
#include <assert.h>

// In-memory settings isolate lifecycle/selection tests from the user's plist.
static NSMutableDictionary *values;
static BOOL failSave;
@implementation VZAppSettings
+ (instancetype)sharedSettings {
    static VZAppSettings *settings;
    if (!settings) { settings = [self new]; values = [NSMutableDictionary new]; }
    return settings;
}
- (NSString *)stringForKey:(NSString *)key { return values[key]; }
- (BOOL)setString:(NSString *)value forKey:(NSString *)key error:(NSError **)error {
    if (failSave) {
        if (error) *error = [NSError errorWithDomain:@"fixture" code:1 userInfo:nil];
        return NO;
    }
    if (value) values[key] = value; else [values removeObjectForKey:key];
    return YES;
}
- (void)setString:(NSString *)value forKey:(NSString *)key {
    [self setString:value forKey:key error:NULL];
}
- (BOOL)boolForKey:(NSString *)key { return [values[key] boolValue]; }
- (void)setBool:(BOOL)value forKey:(NSString *)key { values[key] = @(value); }
- (void)resetToDefaults { [values removeAllObjects]; }
- (NSDictionary *)dictionaryRepresentation { return values; }
@end

static void checkIdentity(void) {
    uint8_t bytes[sizeof(struct mach_header_64) + sizeof(struct uuid_command) +
        sizeof(struct segment_command_64)] = {0};
    struct mach_header_64 h = {.magic=MH_MAGIC_64, .cputype=CPU_TYPE_ARM64,
        .filetype=MH_DYLIB, .ncmds=2, .sizeofcmds=sizeof(bytes)-sizeof(h)};
    struct uuid_command u = {.cmd=LC_UUID,.cmdsize=sizeof(u),.uuid={
        0xdc,0xfc,0x0a,0x79,0x77,0x28,0x30,0x89,
        0x94,0xd7,0x15,0x08,0xe7,0x1f,0x38,0xe5}};
    struct segment_command_64 s = {.cmd=LC_SEGMENT_64,.cmdsize=sizeof(s),
        .segname="__AUTH_CONST",.vmaddr=UINT64_C(0x100140000),.vmsize=0x8000};
    memcpy(bytes,&h,sizeof(h)); memcpy(bytes+sizeof(h),&u,sizeof(u));
    memcpy(bytes+sizeof(h)+sizeof(u),&s,sizeof(s));
    assert(VZIsAuditedVenturaImage(bytes,sizeof(bytes)));
    // Wrong modern/unknown UUID must fail before any slot/protection operation.
    bytes[sizeof(h)+8]^=1; assert(!VZIsAuditedVenturaImage(bytes,sizeof(bytes)));
    bytes[sizeof(h)+8]^=1;
    for (size_t n=0;n<sizeof(bytes);++n) assert(!VZIsAuditedVenturaImage(bytes,n));
    s.vmsize=0x4000;memcpy(bytes+sizeof(h)+sizeof(u),&s,sizeof(s));
    assert(!VZIsAuditedVenturaImage(bytes,sizeof(bytes)));
    s.vmsize=0x8000;memcpy(bytes+sizeof(h)+sizeof(u),&s,sizeof(s));
    u.cmdsize=0;memcpy(bytes+sizeof(h),&u,sizeof(u));
    assert(!VZIsAuditedVenturaImage(bytes,sizeof(bytes)));
}

int main(void) { @autoreleasepool {
    checkIdentity();
    NSError *error=nil;
    assert([VZBackendSelectedVersion() isEqualToString:@"13.2.1"]);
    assert(!VZBackendIsRunActive());
    assert(VZBackendSelectVersion(@"27",&error));
    assert(!VZBackendBeginRun(&error) && error);
    assert(!VZBackendIsRunActive());
    assert(!VZBackendBeginInstallation(&error));
    assert([VZBackendSelectedVersion() isEqualToString:@"27"]); // No fallback.
    assert(!VZBackendSelectVersion(@"garbage",&error));
    assert(VZBackendSelectVersion(@"13.2.1",&error));
    failSave=YES; assert(!VZBackendSelectVersion(@"27",&error));failSave=NO;
    assert([VZBackendSelectedVersion() isEqualToString:@"13.2.1"]);
    assert(VZBackendBeginRun(&error));
    assert(!VZBackendBeginRun(&error));
    assert(!VZBackendSelectVersion(@"27",&error));
    assert(!VZBackendBeginInstallation(&error));
    VZBackendMarkLoadAttempt();VZBackendMarkLoaded();
    assert([VZBackendLoadedVersion() isEqualToString:@"13.2.1"]);
    VZBackendEndRun();
    assert(VZBackendSelectVersion(@"27",&error));
    assert(!VZBackendBeginRun(&error));
    assert([error.localizedDescription isEqualToString:VZBackendAvailabilityReason(@"27")]);
    assert([VZBackendLoadedVersion() isEqualToString:@"13.2.1"]);
    assert(VZBackendSelectVersion(@"13.2.1",&error));
    assert(VZBackendBeginInstallation(&error));
    assert(!VZBackendSelectVersion(@"27",&error));
    assert(!VZBackendBeginRun(&error));
    VZBackendEndInstallation();
    assert(VZBackendBeginRun(&error));VZBackendEndRun();
    puts("PASS: identity rejection, persistence failure, no fallback, run/install exclusion and process lifetime");
} }
