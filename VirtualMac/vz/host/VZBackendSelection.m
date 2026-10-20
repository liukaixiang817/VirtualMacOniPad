#import "VZBackendSelection.h"
#import "VZAppSettings.h"

NSString * const VZFrameworkBackendKey = @"FrameworkBackendVersion";
static NSString *loadedVersion;
static NSString *attemptedVersion;
static NSString *runVersion;
static NSString *runRoot;
static BOOL runActive;
static BOOL installationActive;

static NSError *backendError(NSString *message) {
    return [NSError errorWithDomain:@"VirtualMac.Backend" code:1
        userInfo:@{NSLocalizedDescriptionKey: message}];
}

NSString *VZBackendSelectedVersion(void) {
    NSString *value = [VZAppSettings.sharedSettings stringForKey:VZFrameworkBackendKey];
    // Migrate existing installations without changing their working runtime.
    return value ?: @"13.2.1";
}

NSString *VZBackendLoadedVersion(void) {
    @synchronized (VZAppSettings.sharedSettings) {
        return [[loadedVersion copy] autorelease] ?: VZBL(@"Not loaded");
    }
}

static NSString *baseRuntimeRoot(void) {
    id value = [NSBundle.mainBundle objectForInfoDictionaryKey:@"VirtualMacRuntimeRoot"];
    if ([value isKindOfClass:NSString.class] && [value hasPrefix:@"/"] &&
        [value length] > 1) return [value stringByStandardizingPath];
    return @"/var/root/VirtualMac";
}

static NSString *rootForVersion(NSString *version) {
    if ([version isEqualToString:@"13.2.1"]) return baseRuntimeRoot();
    id value = [NSBundle.mainBundle objectForInfoDictionaryKey:@"VirtualMac27RuntimeRoot"];
    if ([value isKindOfClass:NSString.class] && [value hasPrefix:@"/"] &&
        [value length] > 1) return [value stringByStandardizingPath];
    return [baseRuntimeRoot() stringByAppendingPathComponent:@"backends/macos27"];
}

NSString *VZBackendRuntimeRoot(void) {
    @synchronized (VZAppSettings.sharedSettings) {
        return runActive && runRoot ? [[runRoot copy] autorelease]
            : rootForVersion(VZBackendSelectedVersion());
    }
}

NSString *VZBackendAvailabilityReason(NSString *version) {
    if (![version isEqualToString:@"13.2.1"] && ![version isEqualToString:@"27"])
        return VZBL(@"Unknown framework backend. Choose macOS 13.2.1 or macOS 27 in Settings.");
    // This frontend has only the audited Ventura VZ binding/framebuffer profile.
    // GPU27 is already supported separately; it must not be advertised as CPU27.
    if ([version isEqualToString:@"27"])
        return VZBL(@"macOS 27 CPU, VMM and Virtualization compatibility is still being implemented. This backend cannot start a guest yet. Choose macOS 13.2.1 to use the working backend.");
    return nil;
}

BOOL VZBackendSelectVersion(NSString *version, NSError **error) {
    @synchronized (VZAppSettings.sharedSettings) {
        if (![version isEqualToString:@"13.2.1"] && ![version isEqualToString:@"27"]) {
            if (error) *error = backendError(VZBL(@"Unknown framework backend. Choose macOS 13.2.1 or macOS 27 in Settings."));
            return NO;
        }
        if (runActive || installationActive) {
            if (error) *error = backendError(VZBL(@"Shut down the Virtual Mac before changing its framework backend."));
            return NO;
        }
        return [VZAppSettings.sharedSettings setString:version
            forKey:VZFrameworkBackendKey error:error];
    }
}

BOOL VZBackendBeginRun(NSError **error) {
    @synchronized (VZAppSettings.sharedSettings) {
        NSString *version = VZBackendSelectedVersion();
        NSString *reason = VZBackendAvailabilityReason(version);
        if (runActive || installationActive)
            reason = VZBL(@"A Virtual Mac is already starting or running.");
        else if (!reason && attemptedVersion && ![attemptedVersion isEqualToString:version])
            reason = VZBL(@"Close and reopen Virtual Mac to load the selected framework backend. Different framework versions cannot be loaded in the same app process.");
        if (reason) {
            if (error) *error = backendError(reason);
            return NO;
        }
        runActive = YES;
        [runVersion release]; runVersion = [version copy];
        [runRoot release]; runRoot = [rootForVersion(version) copy];
        return YES;
    }
}

BOOL VZBackendIsRunActive(void) {
    @synchronized (VZAppSettings.sharedSettings) { return runActive || installationActive; }
}

BOOL VZBackendBeginInstallation(NSError **error) {
    @synchronized (VZAppSettings.sharedSettings) {
        NSString *reason = VZBackendAvailabilityReason(VZBackendSelectedVersion());
        if (runActive || installationActive)
            reason = VZBL(@"A Virtual Mac is already starting or running.");
        if (reason) {
            if (error) *error = backendError(reason);
            return NO;
        }
        installationActive = YES;
        return YES;
    }
}

void VZBackendEndInstallation(void) {
    @synchronized (VZAppSettings.sharedSettings) { installationActive = NO; }
}

void VZBackendMarkLoadAttempt(void) {
    @synchronized (VZAppSettings.sharedSettings) {
        if (!attemptedVersion) attemptedVersion = [runVersion copy];
    }
}

void VZBackendMarkLoaded(void) {
    @synchronized (VZAppSettings.sharedSettings) {
        [loadedVersion release]; loadedVersion = [runVersion copy];
    }
}

void VZBackendEndRun(void) {
    @synchronized (VZAppSettings.sharedSettings) { runActive = NO; }
}
