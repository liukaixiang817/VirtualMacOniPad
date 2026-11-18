// Stage the user-space USB camera alongside the combined radio setup. Guest
// activation uses the policy after the existing owner-authorized restart.
static void VM27CameraProvisionV1(uint64_t generation, void (^completion)(void)) {
    NSString *bundle = [[gGuestBundlePath copy] autorelease];
    if (!VM27RadioProvisionLiveV1(generation, bundle)) return;
    NSDictionary *options = [NSDictionary dictionaryWithContentsOfFile:[bundle stringByAppendingPathComponent:@"VirtualMac.plist"]];
    if (![options[@"BuiltInCameraDevice"] isEqual:@YES] || ![options[@"AutomaticRadioInstallationV1"] isEqual:@YES]) {
        completion();
        return;
    }
    NSString *resources = [NSBundle.mainBundle.resourcePath stringByAppendingPathComponent:@"Camera"];
    NSDictionary *manifest = [NSDictionary dictionaryWithContentsOfFile:[resources stringByAppendingPathComponent:@"Manifest.plist"]];
    NSString *digest = manifest[@"ProgramSHA256"], *jobDigest = manifest[@"JobSHA256"];
    NSData *program = [NSData dataWithContentsOfFile:[resources stringByAppendingPathComponent:@"virtualmac-camera-daemon"]];
    NSData *job = [NSData dataWithContentsOfFile:[resources stringByAppendingPathComponent:@"com.virtualmac.camera-v1.plist"]];
    if (program.length > 1024 * 1024 || job.length > 4096 ||
        !VM27RadioPackageHashV1(program, digest) || !VM27RadioPackageHashV1(job, jobDigest)) {
        VZGuestToolsLog(@"camera provisioning resources failed integrity verification");
        completion();
        return;
    }
    NSString *path = @"/Library/PrivilegedHelperTools/com.virtualmac.CameraV1";
    NSString *plist = @"/Library/LaunchDaemons/com.virtualmac.camera-v1.plist";
    NSString *launch = @"/bin/launchctl print system/com.virtualmac.camera-v1 >/dev/null 2>&1 || "
        "/bin/launchctl bootstrap system /Library/LaunchDaemons/com.virtualmac.camera-v1.plist";
    NSString *check = [NSString stringWithFormat:@"set -eu; test ! -L %@; test ! -L %@; "
        "test \"$(/usr/bin/shasum -a 256 %@ | /usr/bin/cut -d ' ' -f1)\" = %@; "
        "test \"$(/usr/bin/shasum -a 256 %@ | /usr/bin/cut -d ' ' -f1)\" = %@; %@",
        path, plist, path, VM27RadioShellQuoteV1(digest), plist, VM27RadioShellQuoteV1(jobDigest), launch];
    VZGuestToolsRun(@"/bin/sh", @[@"-c", check], ^(BOOL ready, NSData *ignored) {
        (void)ignored;
        if (!VM27RadioProvisionLiveV1(generation, bundle)) return;
        if (ready) { completion(); return; }
        NSString *stage = [@"/private/var/root/VirtualMacCamera." stringByAppendingString:NSUUID.UUID.UUIDString];
        NSString *make = [NSString stringWithFormat:@"test -f /var/db/.AppleSetupDone && /bin/mkdir -m 700 %@", VM27RadioShellQuoteV1(stage)];
        VZGuestToolsRun(@"/bin/sh", @[@"-c", make], ^(BOOL made, NSData *unused) {
            (void)unused;
            if (!VM27RadioProvisionLiveV1(generation, bundle)) return;
            if (!made) { completion(); return; }
            VZGuestToolsWriteFile([stage stringByAppendingPathComponent:@"daemon"], program, ^(BOOL wroteProgram) {
                if (!VM27RadioProvisionLiveV1(generation, bundle)) return;
                if (!wroteProgram) { completion(); return; }
                VZGuestToolsWriteFile([stage stringByAppendingPathComponent:@"job"], job, ^(BOOL wroteJob) {
                    if (!VM27RadioProvisionLiveV1(generation, bundle)) return;
                    if (!wroteJob) { completion(); return; }
                    NSString *install = [NSString stringWithFormat:@"set -eu; cd %@; "
                        "test \"$(/usr/bin/shasum -a 256 daemon | /usr/bin/cut -d ' ' -f1)\" = %@; "
                        "test \"$(/usr/bin/shasum -a 256 job | /usr/bin/cut -d ' ' -f1)\" = %@; "
                        "/usr/bin/codesign --verify --strict daemon; /usr/bin/plutil -lint job; "
                        "test ! -L %@; test ! -L %@; "
                        "if test ! -e %@; then /bin/chmod 755 daemon; /usr/sbin/chown root:wheel daemon; /bin/mv daemon %@; fi; "
                        "if test ! -e %@; then /bin/chmod 644 job; /usr/sbin/chown root:wheel job; /bin/mv job %@; fi; "
                        "%@; /bin/rm -f daemon job; cd /; /bin/rmdir %@",
                        VM27RadioShellQuoteV1(stage), VM27RadioShellQuoteV1(digest), VM27RadioShellQuoteV1(jobDigest),
                        path, plist, path, path, plist, plist, check, VM27RadioShellQuoteV1(stage)];
                    VZGuestToolsRun(@"/bin/sh", @[@"-c", install], ^(BOOL installed, NSData *output) {
                        (void)output;
                        if (!VM27RadioProvisionLiveV1(generation, bundle)) return;
                        VZGuestToolsLog(@"camera provisioning %@", installed ? @"ready to activate after owner authorization" : @"failed");
                        completion();
                    });
                });
            });
        });
    });
}
