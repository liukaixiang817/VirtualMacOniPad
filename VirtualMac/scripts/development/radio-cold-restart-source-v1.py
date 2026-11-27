"""Wire the audited 27.2.1 radio restart through normal VM shutdown/teardown."""


def apply(source, radio):
    def replace(old, new):
        nonlocal source
        if source.count(old) != 1:
            raise ValueError('radio cold restart insertion point changed: ' + old[:80])
        source = source.replace(old, new)

    replace('#import "VMAppleAccountInstallationV1.h"',
            '#import "VMAppleAccountInstallationV1.h"\n#import "' +
            str(radio / 'host/VM27RadioColdRestartV1.h') + '"')
    replace('static BOOL gForceStopPending;',
            'static BOOL gForceStopPending;\n#include "' +
            str(radio / 'host/VM27RadioColdRestartUIV1.inc') + '"')
    replace('- (void)confirmForceShutdown;',
            '- (void)confirmForceShutdown;\n- (void)radioColdRestartRequestedV1:(NSNotification *)notification;')
    replace('    [machineActions addObject:shutdown];', '''    NSDictionary *radioBoot = self.activeVMBundlePath.length ? [NSDictionary dictionaryWithContentsOfFile:
        [self.activeVMBundlePath stringByAppendingPathComponent:@"AutomaticRadio26-v1/Boot.plist"]] : nil;
    if (gVirtualMachine && VZIndependent27SourceRouteSelected() && [radioBoot[@"GuestBuild"] isEqual:@"26B131"]) {
        UIAction *restart = [UIAction actionWithTitle:VZL(@"Restart") image:[UIImage systemImageNamed:@"arrow.clockwise"]
            identifier:nil handler:^(UIAction *action) {
            (void)action;NSString *bundle=[[self.activeVMBundlePath copy] autorelease];
            VM27RadioRequestColdRestartV1(bundle,^(BOOL success){
                if(!success)VZPresentFailureReport(self,VZL(@"Could Not Restart Virtual Mac"),
                    VZL(@"Finish radio setup and try again, or shut down macOS normally before starting it again."),nil,VZFailureSupportOptionNone);
            });
        }];
        if(VM27HibernateOperationPendingV4() || VM27RadioColdBundleV1)restart.attributes|=UIMenuElementAttributesDisabled;
        [machineActions addObject:restart];
    }
    [machineActions addObject:shutdown];''')
    replace('- (void)confirmForceShutdown\n{',
            '#include "' + str(radio / 'host/VM27RadioColdRestartMethodsV1.inc') +
            '"\n\n- (void)confirmForceShutdown\n{')
    replace('static void startVirtualMachine(UIView *container, id delegate,\n'
            '                                NSString *bundlePath,\n'
            '                                NSDictionary *options) {',
            'static void startVirtualMachine(UIView *container, id delegate,\n'
            '                                NSString *bundlePath,\n'
            '                                NSDictionary *options) {\n'
            '    VM27RadioObserveColdRestartV1();')
    replace('static void forceStopVirtualMachine(void) {\n'
            '    if (!gVirtualMachine || gForceStopPending || VM27HibernateOperationPendingV4())\n'
            '        return;',
            'static void forceStopVirtualMachine(void) {\n'
            '    if (!gVirtualMachine || gForceStopPending || VM27HibernateOperationPendingV4())\n'
            '        return;\n'
            '    VM27RadioCancelColdRestartV1();')
    replace('    self.activeVMBundlePath = nil;\n'
            '    [self presentVMLibrary];\n'
            '    if ([error.domain isEqualToString:@"VirtualMac.Backend"]) {',
            '''    NSString *radioRestart = !error && [VM27RadioColdBundleV1 isEqual:self.activeVMBundlePath] ?
        [VM27RadioColdBundleV1 copy] : nil;
    VM27RadioCancelColdRestartV1();
    self.activeVMBundlePath = nil;
    [self presentVMLibrary];
    if (radioRestart) dispatch_async(dispatch_get_main_queue(), ^{
        if (!gVirtualMachine && !VZBackendIsRunActive()) {
            printf("[VirtualMac] radio cold restart: native teardown completed, starting same guest\\n");
            [self vmLibrary:nil bootBundleAtPath:radioRestart options:VZVMOptionsForBundle(radioRestart)];
        }
        [radioRestart release];
    });
    if ([error.domain isEqualToString:@"VirtualMac.Backend"]) {''')
    return source
