// Included by the existing owned QGA implementation after its Run/WriteFile
// helpers. Uses that same connection, epoch, serial queue and operation bounds.
// Independent of optional Guest Tools and of the user's account name/password.
static BOOL VM27RadioProvisionLiveV1(uint64_t generation, NSString *bundle) {
    return generation == __atomic_load_n(&gGuestProvisioningGeneration, __ATOMIC_ACQUIRE) &&
        [bundle isEqual:gGuestBundlePath] && gGuestReadDescriptor >= 0;
}
static NSString *VM27RadioShellQuoteV1(NSString *text) {
    return [NSString stringWithFormat:@"'%@'", [text stringByReplacingOccurrencesOfString:@"'" withString:@"'\\''"]];
}
static BOOL VM27RadioPackageHashV1(NSData *data, id expected) {
    if (![expected isKindOfClass:NSString.class] || [expected length] != 64 || !data.length) return NO;
    unsigned char digest[CC_SHA256_DIGEST_LENGTH]; CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    NSMutableString *actual = [NSMutableString stringWithCapacity:64];
    for (unsigned i = 0; i < sizeof(digest); ++i) [actual appendFormat:@"%02x", digest[i]];
    return [actual isEqual:expected];
}
static void VM27RadioProvisionRecordV1(uint64_t generation, NSString *bundle, NSString *state) {
    if (!VM27RadioProvisionLiveV1(generation, bundle)) return;
    NSDictionary *record = @{@"Schema":@1, @"State":state, @"GuestAgentGeneration":@(generation),
        @"NativeWiFiConnectionVerified":@NO, @"NativeBluetoothPairingImplemented":@NO};
    [record writeToFile:[bundle stringByAppendingPathComponent:@"SharedRadioProvisioning.plist"] atomically:YES];
    VZGuestToolsLog(@"shared radio provisioning: %@", state);
}
static void VM27RadioProvisionActivationStatusV1(uint64_t generation, NSString *bundle,
    NSUInteger attempt, void (^completion)(void)) {
    if (!VM27RadioProvisionLiveV1(generation, bundle)) return;
    VZGuestToolsRun(@"/Library/PrivilegedHelperTools/com.virtualmac.RadioFirstBootV1", @[@"--status"],
        ^(BOOL success, NSData *output) {
        if (!VM27RadioProvisionLiveV1(generation, bundle)) return;
        id status = success && output.length <= 16384 ? [NSJSONSerialization JSONObjectWithData:output options:0 error:NULL] : nil;
        NSSet *states = [NSSet setWithArray:@[@"guest-policy-required", @"native-driver-activation-required",
            @"native-wifi-interface-disabled", @"starting-radio-services", @"native-radio-components-ready",
            @"native-activation-reboot-required", @"policy-readback-unavailable", @"boot-arguments-require-attention",
            @"guest-policy-requires-attention", @"native-driver-requires-attention"]];
        NSString *state = [status isKindOfClass:NSDictionary.class] ? status[@"State"] : nil;
        if (![states containsObject:state]) state = @"activation-status-unavailable";
        VM27RadioProvisionRecordV1(generation, bundle, state);
        if (([state isEqual:@"starting-radio-services"] || [state isEqual:@"activation-status-unavailable"]) && attempt < 12) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 5*NSEC_PER_SEC), QGAQueueV3(), ^{
                if (VM27RadioProvisionLiveV1(generation, bundle))
                    VM27RadioProvisionActivationStatusV1(generation, bundle, attempt+1, completion);
            });
        } else completion();
    });
}
static void VM27RadioProvisionUploadV1(uint64_t generation, NSString *bundle, NSString *directory,
    NSDictionary *entry, NSData *installer, NSData *archive, void (^completion)(void)) {
    if (!VM27RadioProvisionLiveV1(generation, bundle)) return;
    VZGuestToolsWriteFile([directory stringByAppendingPathComponent:@"installer"], installer, ^(BOOL wrote) {
        if (!VM27RadioProvisionLiveV1(generation, bundle)) return;
        if (!wrote) { VM27RadioProvisionRecordV1(generation,bundle,@"installer-upload-failed"); completion(); return; }
        VZGuestToolsWriteFile([directory stringByAppendingPathComponent:@"payload.tar"], archive, ^(BOOL uploaded) {
            if (!VM27RadioProvisionLiveV1(generation, bundle)) return;
            if (!uploaded) { VM27RadioProvisionRecordV1(generation,bundle,@"payload-upload-failed"); completion(); return; }
            // The newly-created directory belongs to root, mode 0700. Hash both
            // uploaded files before extraction/execution, using signed resources.
            NSString *script = [NSString stringWithFormat:
                @"set -eu; cd %@; test \"$(/usr/bin/id -u)\" = 0; "
                 "test \"$(/usr/bin/shasum -a 256 installer | /usr/bin/cut -d ' ' -f 1)\" = %@; "
                 "test \"$(/usr/bin/shasum -a 256 payload.tar | /usr/bin/cut -d ' ' -f 1)\" = %@; "
                 "/bin/chmod 700 installer; /usr/bin/tar -xf payload.tar; "
                 "./installer --stage \"$PWD/Package\" %@",
                VM27RadioShellQuoteV1(directory), VM27RadioShellQuoteV1(entry[@"InstallerSHA256"]),
                VM27RadioShellQuoteV1(entry[@"ArchiveSHA256"]), VM27RadioShellQuoteV1(entry[@"ManifestSHA256"])];
            VZGuestToolsRun(@"/bin/sh", @[@"-c",script], ^(BOOL success, NSData *output) {
                if (!VM27RadioProvisionLiveV1(generation,bundle)) return;
                NSString *text = [[[NSString alloc] initWithData:output encoding:NSUTF8StringEncoding] autorelease];
                BOOL staged = success && [text containsString:@"VM27_RADIO_COMPONENTS_STAGED"];
                VM27RadioProvisionRecordV1(generation,bundle,staged ? @"components-staged-awaiting-activation" : @"component-staging-failed");
                // Retain the bounded, root-only upload on failure for diagnosis.
                // Never infer radio functionality from this receipt.
                if (!staged) { completion(); return; }
                NSString *cleanup = [NSString stringWithFormat:@"/bin/rm -rf %@",VM27RadioShellQuoteV1(directory)];
                VZGuestToolsRun(@"/bin/sh",@[@"-c",cleanup],^(BOOL removed,NSData *ignored) {
                    (void)ignored;
                    if (!VM27RadioProvisionLiveV1(generation,bundle)) return;
                    if (!removed) VZGuestToolsLog(@"shared radio private upload retained after cleanup failure");
                    if ([entry[@"CombinedInstallation"] isEqual:@YES])
                        VM27RadioProvisionActivationStatusV1(generation, bundle, 0, completion);
                    else completion();
                });
            });
        });
    });
}
static void VM27SharedRadioProvisionStartV1(uint64_t generation, NSUInteger attempt, void (^completion)(void)) {
    NSString *bundle = [[gGuestBundlePath copy] autorelease];
    if (!VM27RadioProvisionLiveV1(generation,bundle)) return;
    const char *backend = getenv("VZ_PVG_BACKEND_VERSION");
    if (!backend || strcmp(backend,"27")) { completion(); return; }
    NSDictionary *options = [NSDictionary dictionaryWithContentsOfFile:[bundle stringByAppendingPathComponent:@"VirtualMac.plist"]];
    if ([options[@"SharedRadioEnabledV1"] isEqual:@NO]) { completion(); return; }
    NSString *resources = [NSBundle.mainBundle.resourcePath stringByAppendingPathComponent:@"SharedRadio"];
    NSDictionary *catalog = [NSDictionary dictionaryWithContentsOfFile:[resources stringByAppendingPathComponent:@"Catalog.plist"]];
    if (![catalog[@"Schema"] isEqual:@1] || ![catalog[@"Packages"] isKindOfClass:NSDictionary.class]) {
        VM27RadioProvisionRecordV1(generation,bundle,@"package-not-bundled"); completion(); return;
    }
    NSString *probe = @"set -eu; test \"$(/usr/bin/id -u)\" = 0; "
        "test -f /var/db/.AppleSetupDone || exit 75; /usr/bin/sw_vers -buildVersion";
    VZGuestToolsRun(@"/bin/sh",@[@"-c",probe],^(BOOL success,NSData *output) {
        if (!VM27RadioProvisionLiveV1(generation,bundle)) return;
        if (!success) {
            // Setup Assistant may legitimately take more than 30 minutes.
            // Keep one bounded probe alive for this actual VM connection;
            // slowing the retry must not permanently skip its installation.
            if (attempt == 120) VM27RadioProvisionRecordV1(generation,bundle,@"waiting-for-setup-or-root-agent");
            NSUInteger nextAttempt = attempt < 121 ? attempt + 1 : 121;
            int64_t delay = attempt < 120 ? 15 : 60;
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW,delay*NSEC_PER_SEC),QGAQueueV3(),^{
                if (VM27RadioProvisionLiveV1(generation,bundle)) VM27SharedRadioProvisionStartV1(generation,nextAttempt,completion);
            }); return;
        }
        NSString *build = [[[[NSString alloc] initWithData:output encoding:NSUTF8StringEncoding] autorelease]
            stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
        BOOL automatic = [options[@"AutomaticRadioInstallationV1"] isEqual:@YES] &&
            [catalog[@"AutomaticPackages"][build] isKindOfClass:NSDictionary.class];
        NSDictionary *entry = catalog[automatic ? @"AutomaticPackages" : @"Packages"][build];
        if (![entry isKindOfClass:NSDictionary.class]) {
            VM27RadioProvisionRecordV1(generation,bundle,@"unsupported-guest-build"); completion(); return;
        }
        NSString *payloadResources = resources;
        id subdirectory = entry[@"ResourceDirectory"];
        if (subdirectory) {
            NSString *expectedDirectory = automatic ? [@"Automatic" stringByAppendingString:build] : build;
            if (![subdirectory isKindOfClass:NSString.class] || ![subdirectory isEqual:expectedDirectory] ||
                [subdirectory rangeOfCharacterFromSet:[[NSCharacterSet characterSetWithCharactersInString:@"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"] invertedSet]].location != NSNotFound) {
                VM27RadioProvisionRecordV1(generation,bundle,@"invalid-package-directory"); completion(); return;
            }
            payloadResources = [resources stringByAppendingPathComponent:subdirectory];
        }
        for (NSString *key in @[@"Archive",@"Installer"]) {
            id name = entry[key];
            if (![name isKindOfClass:NSString.class] || ![name length] || ![name isEqual:[name lastPathComponent]] || [name isEqual:@"."] || [name isEqual:@".."]) {
                VM27RadioProvisionRecordV1(generation,bundle,@"invalid-package-catalog"); completion(); return;
            }
        }
        id manifestHash = entry[@"ManifestSHA256"];
        if (![manifestHash isKindOfClass:NSString.class] || [manifestHash length] != 64 ||
            [manifestHash rangeOfCharacterFromSet:[[NSCharacterSet characterSetWithCharactersInString:@"0123456789abcdef"] invertedSet]].location != NSNotFound) {
            VM27RadioProvisionRecordV1(generation,bundle,@"invalid-package-catalog"); completion(); return;
        }
        NSString *prior = automatic ?
            @"case \"$(/usr/libexec/PlistBuddy -c 'Print :CombinedInstallation' /Library/VirtualMac/SharedRadio/Provisioning.plist 2>/dev/null)\" in true|1) "
             "/usr/libexec/PlistBuddy -c 'Print :PackageManifestSHA256' /Library/VirtualMac/SharedRadio/Provisioning.plist 2>/dev/null || true;; esac" :
            @"/usr/libexec/PlistBuddy -c 'Print :PackageManifestSHA256' /Library/VirtualMac/SharedRadio/Provisioning.plist 2>/dev/null || true";
        VZGuestToolsRun(@"/bin/sh",@[@"-c",prior],^(BOOL read,NSData *receipt) {
            if (!VM27RadioProvisionLiveV1(generation,bundle)) return;
            NSString *saved = [[[[NSString alloc] initWithData:receipt encoding:NSUTF8StringEncoding] autorelease]
                stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
            // A newly-created guest is pinned to its first complete combined
            // installation. A later App's package is for later new guests;
            // helper migration requires a separate, validated implementation.
            BOOL pinnedCombined = automatic && saved.length == 64 &&
                [saved rangeOfCharacterFromSet:[[NSCharacterSet characterSetWithCharactersInString:@"0123456789abcdef"] invertedSet]].location == NSNotFound;
            if (read && ([saved isEqual:manifestHash] || pinnedCombined)) {
                if (automatic) VM27RadioProvisionActivationStatusV1(generation, bundle, 0, completion);
                else { VM27RadioProvisionRecordV1(generation,bundle,@"components-current-awaiting-activation"); completion(); }
                return;
            }
            NSData *archive = [NSData dataWithContentsOfFile:[payloadResources stringByAppendingPathComponent:entry[@"Archive"]]];
            NSData *installer = [NSData dataWithContentsOfFile:[payloadResources stringByAppendingPathComponent:entry[@"Installer"]]];
            if (archive.length > 16*1024*1024 || installer.length > 1024*1024 ||
                !VM27RadioPackageHashV1(archive,entry[@"ArchiveSHA256"]) || !VM27RadioPackageHashV1(installer,entry[@"InstallerSHA256"])) {
                VM27RadioProvisionRecordV1(generation,bundle,@"package-integrity-failed"); completion(); return;
            }
            VZGuestToolsRun(@"/bin/sh",@[@"-c",@"umask 077; /usr/bin/mktemp -d /private/var/root/VirtualMacRadio.XXXXXXXX"],^(BOOL made,NSData *result) {
                if (!VM27RadioProvisionLiveV1(generation,bundle)) return;
                NSString *directory = [[[[NSString alloc] initWithData:result encoding:NSUTF8StringEncoding] autorelease]
                    stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
                NSString *prefix = @"/private/var/root/VirtualMacRadio.";
                NSString *suffix = [directory hasPrefix:prefix] ? [directory substringFromIndex:prefix.length] : nil;
                if (!made || suffix.length != 8 || [suffix rangeOfCharacterFromSet:[[NSCharacterSet alphanumericCharacterSet] invertedSet]].location != NSNotFound) {
                    VM27RadioProvisionRecordV1(generation,bundle,@"private-staging-unavailable"); completion(); return;
                }
                VM27RadioProvisionUploadV1(generation,bundle,directory,entry,installer,archive,completion);
            });
        });
    });
}
