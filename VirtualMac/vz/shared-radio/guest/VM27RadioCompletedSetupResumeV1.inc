// The child runs as the actual owner: use the supported CurrentUser and
// CurrentHost CFPreferences domains, never direct plist edits or cfprefsd kills.
static int ownerSetupResumeV1(BOOL apply) {
    if (getuid() < 500 || getuid() != geteuid() || setupAssistantStatus() != ENOENT) return EAGAIN;
    struct stat done;
    if (lstat("/var/db/.AppleSetupDone", &done) || !S_ISREG(done.st_mode) || done.st_uid) return EAGAIN;
    CFStringRef setup = CFSTR("com.apple.SetupAssistant"), domain = CFSTR("com.apple.loginwindow");
    if (!CFPreferencesSynchronize(setup, kCFPreferencesCurrentUser, kCFPreferencesAnyHost) ||
        !CFPreferencesSynchronize(domain, kCFPreferencesCurrentUser, kCFPreferencesCurrentHost)) return EIO;
    NSDictionary *preferences = CFBridgingRelease(CFPreferencesCopyMultiple(
        (__bridge CFArrayRef)@[@"LastSeenBuddyBuildVersion", @"DidSeeCloudSetup", @"MiniBuddyShouldLaunchToResumeSetup"],
        setup, kCFPreferencesCurrentUser, kCFPreferencesAnyHost));
    if (!VM27RadioSetupPreferencesCompletedV1(preferences, @VM27_RADIO_GUEST_BUILD)) return EAGAIN;
    id original = CFBridgingRelease(CFPreferencesCopyValue(CFSTR("TALAppsToRelaunchAtLogin"), domain,
        kCFPreferencesCurrentUser, kCFPreferencesCurrentHost));
    NSUInteger removed = 0;
    NSArray *updated = original ? VM27RadioPrunedSetupResumeV1(original, &removed) : @[];
    if (!updated) return EINVAL;
    NSDictionary *record = @{@"Schema":@1, @"GuestBuild":@VM27_RADIO_GUEST_BUILD, @"OwnerUID":@(getuid()),
        @"ResumeKeyPresent":@(original != nil), @"ResumeList":original ?: @[], @"RemovedSetupEntries":@(removed)};
    NSData *data = [NSPropertyListSerialization dataWithPropertyList:record format:NSPropertyListXMLFormat_v1_0 options:0 error:NULL];
    if (!data || data.length > 16384) return EOVERFLOW;
    if (apply) {
        // Parent saved this exact value privately before requesting a write.
        // If loginwindow changed it meanwhile, retry instead of overwriting.
        NSMutableData *expectedData = [NSMutableData data];
        for (;;) {
            NSData *chunk = [NSFileHandle.fileHandleWithStandardInput readDataUpToLength:16385 - expectedData.length error:NULL];
            if (!chunk) return EIO;
            if (!chunk.length) break;
            [expectedData appendData:chunk];
            if (expectedData.length > 16384) return EOVERFLOW;
        }
        id expected = [NSPropertyListSerialization propertyListWithData:expectedData options:0 format:NULL error:NULL];
        if (![record isEqual:expected]) return EAGAIN;
        if (removed) {
            CFPreferencesSetValue(CFSTR("TALAppsToRelaunchAtLogin"), (__bridge CFArrayRef)updated, domain,
                kCFPreferencesCurrentUser, kCFPreferencesCurrentHost);
            if (!CFPreferencesSynchronize(domain, kCFPreferencesCurrentUser, kCFPreferencesCurrentHost)) return EIO;
            id actual = CFBridgingRelease(CFPreferencesCopyValue(CFSTR("TALAppsToRelaunchAtLogin"), domain,
                kCFPreferencesCurrentUser, kCFPreferencesCurrentHost));
            if (![actual isEqual:updated]) return EIO;
        }
    } else {
        [NSFileHandle.fileHandleWithStandardOutput writeData:data];
    }
    return 0;
}

static int settleOwnerSetupResumeV1(uid_t uid) {
    NSString *ownerUID = [NSString stringWithFormat:@"%u", uid];
    NSString *sudoOwner = [@"#" stringByAppendingString:ownerUID];
    // A system LaunchDaemon must adopt the owner's bootstrap namespace to
    // reach their cfprefsd. sudo separately switches credentials and home.
    NSArray *prefix = @[@"asuser", ownerUID, @"/usr/bin/sudo", @"-H", @"-u", sudoOwner, @"--", @(Self)];
    int result = 0;
    NSData *data = run(@"/bin/launchctl", [prefix arrayByAddingObject:@"--inspect-owner-setup-resume"], nil, &result, 10);
    if (result) return result;
    if (!data.length || data.length > 16384) return EOVERFLOW;
    id record = [NSPropertyListSerialization propertyListWithData:data options:0 format:NULL error:NULL];
    if (![record isKindOfClass:NSDictionary.class] || ![record[@"OwnerUID"] isEqual:@(uid)] ||
        ![record[@"GuestBuild"] isEqual:@VM27_RADIO_GUEST_BUILD]) return EINVAL;
    if (![record[@"RemovedSetupEntries"] unsignedIntegerValue]) return 0;
    NSString *backup = [Root stringByAppendingPathComponent:[NSString stringWithFormat:@"CompletedSetupResumeBefore-%u.plist", uid]];
    struct stat st;
    if (lstat(backup.fileSystemRepresentation, &st)) {
        if (errno != ENOENT || ![data writeToFile:backup options:NSDataWritingWithoutOverwriting error:NULL] ||
            chmod(backup.fileSystemRepresentation, 0600)) return EIO;
    } else if (!S_ISREG(st.st_mode) || st.st_uid || st.st_nlink != 1 || (st.st_mode & 0777) != 0600) return EPERM;
    run(@"/bin/launchctl", [prefix arrayByAddingObject:@"--apply-owner-setup-resume"], data, &result, 10);
    return result;
}
