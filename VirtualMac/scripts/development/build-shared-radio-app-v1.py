#!/usr/bin/env python3
"""Build the App with the genuine VZ shared-radio stream adapter.

Reuses the exact Beta6-r2 objects, replacing only its primary compilation and
adding owned radio sources. Does not deploy, modify runtime providers, or claim
that a native guest radio interface has been created.
"""
import argparse
import hashlib
import json
from pathlib import Path
import plistlib
import re
import shutil
import subprocess
import tempfile


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def add_builtin_audio(source):
    def replace(old, new):
        nonlocal source
        if source.count(old) != 1:
            raise ValueError(f"built-in audio insertion point changed ({old.splitlines()[0]})")
        source = source.replace(old, new)

    replace('#import <AVFAudio/AVFAudio.h>',
            '#import <AVFAudio/AVFAudio.h>\n#import "VM27BuiltInAudio.h"')
    replace('    self.installationOptions = radioNewGuestOptions;',
            '    if (VZIndependent27SourceRouteSelected()) radioNewGuestOptions[VM27BuiltInAudioKey] = @YES;\n'
            '    self.installationOptions = radioNewGuestOptions;')
    replace('    [machineActions addObject:shutdown];',
            '    NSArray *audioActions = @[];\n'
            '    if (gVirtualMachine && self.activeVMBundlePath.length && VZIndependent27SourceRouteSelected()) {\n'
            '        NSDictionary *options = VZVMOptionsForBundle(self.activeVMBundlePath);\n'
            '        if (VM27UsesBuiltInAudio(YES, options))\n'
            '            audioActions = @[[self builtInAudioMenuForOptions:options microphone:YES],\n'
            '                [self builtInAudioMenuForOptions:options microphone:NO]];\n'
            '    }\n'
            '    // UIKit reverses inline items when the floating menu opens upward.\n'
            '    if (bottom) [machineActions addObjectsFromArray:audioActions.reverseObjectEnumerator.allObjects];\n'
            '    [machineActions addObject:shutdown];\n'
            '    if (!bottom) [machineActions addObjectsFromArray:audioActions];')
    replace('- (void)confirmForceShutdown\n{',
            '#include "VM27BuiltInAudioMenu.inc"\n\n- (void)confirmForceShutdown\n{')
    replace('    if (!outputEnabled && !inputEnabled) {',
            '    BOOL builtInAudio = VM27UsesBuiltInAudio(independent27, options);\n'
            '    if (!builtInAudio && !outputEnabled && !inputEnabled) {')
    replace('    if(independent27) {\n        AVAudioSession *session=AVAudioSession.sharedInstance;',
            '    if(independent27 && (inputEnabled || outputEnabled)) {\n        AVAudioSession *session=AVAudioSession.sharedInstance;')
    replace('    id sink = outputEnabled ? NEW("VZHostAudioOutputStreamSink") : nil;',
            '''    if (builtInAudio) {
        if (!VM27ConfigureBuiltInAudio(configuration, inputEnabled, outputEnabled))
            @throw [NSException exceptionWithName:@"VM27InvalidNativeAudioProfile"
                reason:@"The native sound device did not retain its built-in streams." userInfo:nil];
        printf("[VirtualMac] built-in audio inputStream=1 outputStream=1 microphoneShared=%d speakersShared=%d\\n",
            inputEnabled, outputEnabled);
        return;
    }
    id sink = outputEnabled ? NEW("VZHostAudioOutputStreamSink") : nil;''')
    replace('    static BOOL microphoneRequestPending=NO;',
            '''    if (VM27UsesBuiltInAudio(VZIndependent27SourceRouteSelected(), options) && !VZBackendIsRunActive()) {
        NSError *savedStateError = nil;
        if (!VM27HibernateReadV4(bundlePath, &savedStateError) && !savedStateError) {
            NSDictionary *saved = VZVMOptionsForBundle(bundlePath);
            NSMutableDictionary *updated = [[saved mutableCopy] autorelease];
            VM27ApplyBuiltInAudioPreferences(updated,
                AVAudioSession.sharedInstance.recordPermission != AVAudioSessionRecordPermissionDenied);
            if (![updated isEqualToDictionary:saved]) {
                NSError *writeError = nil;
                if (!VZWriteVMOptions(updated, bundlePath, &writeError)) {
                    finishVMThreadSafe(delegate, writeError);
                    return;
                }
            }
            NSMutableDictionary *runtime = [[options mutableCopy] autorelease];
            runtime[VM27SpeakerKey] = updated[VM27SpeakerKey];
            runtime[VM27MicrophoneKey] = updated[VM27MicrophoneKey];
            options = runtime;
        }
    }
    static BOOL microphoneRequestPending=NO;''')
    replace('                    else finishVMThreadSafe(delegate,[NSError errorWithDomain:@"VirtualMac.Microphone" code:2',
            '                    else if (VM27UsesBuiltInAudio(YES, options) &&\n'
            '                            session.recordPermission == AVAudioSessionRecordPermissionDenied)\n'
            '                        startVirtualMachine(container,delegate,bundlePath,options);\n'
            '                    else finishVMThreadSafe(delegate,[NSError errorWithDomain:@"VirtualMac.Microphone" code:2')
    return source


def add_builtin_camera(source):
    def insert(old, new):
        nonlocal source
        if source.count(old) != 1:
            raise ValueError(f"built-in camera insertion point changed ({old.splitlines()[0]})")
        source = source.replace(old, new)

    insert('#import "VM27BuiltInAudio.h"',
           '#import "VM27BuiltInAudio.h"\n#import "VM27HostCamera.h"\n\nstatic VM27HostCamera *gGuestCamera;')
    insert('    self.installationOptions = radioNewGuestOptions;',
           '    if (VZIndependent27SourceRouteSelected()) radioNewGuestOptions[@"BuiltInCameraDevice"] = @YES;\n'
           '    self.installationOptions = radioNewGuestOptions;')
    insert('    // UIKit reverses inline items when the floating menu opens upward.',
           '    if (gGuestCamera) audioActions = [@[[self cameraMenu]] arrayByAddingObjectsFromArray:audioActions];\n'
           '    // UIKit reverses inline items when the floating menu opens upward.')
    insert('#include "VM27BuiltInAudioMenu.inc"',
           '#include "VM27BuiltInAudioMenu.inc"\n#include "VM27CameraMenu.inc"')
    insert('    VZGuestToolsAttachToVirtualMachine(gVirtualMachine);',
           '    if (VZIndependent27SourceRouteSelected() && [options[@"BuiltInCameraDevice"] isEqual:@YES]) {\n'
           '        gGuestCamera = [[VM27HostCamera alloc] initWithVirtualMachine:gVirtualMachine profile:VM27CameraProfile480p];\n'
           '        [gGuestCamera setEligible:UIApplication.sharedApplication.applicationState == UIApplicationStateActive];\n'
           '    }\n'
           '    VZGuestToolsAttachToVirtualMachine(gVirtualMachine);')
    insert('    gVirtualMachine = nil;',
           '    [gGuestCamera invalidate];\n    [gGuestCamera release];\n    gGuestCamera = nil;\n    gVirtualMachine = nil;')
    insert('    BOOL owns = active && self.isVMDisplayActive;',
           '    BOOL owns = active && self.isVMDisplayActive;\n    [gGuestCamera setEligible:owns];')
    return source


def build_camera_tools(root, out, run):
    camera = root / 'VirtualMac/vz/camera'
    shared = root / 'VirtualMac/vz/shared'
    host_objects = []
    for name, source in [('camera-host', camera / 'VM27HostCamera.m'),
                         ('camera-encode-nv12', camera / 'VM27CameraEncodeNV12JPEG.m'),
                         ('camera-frames', shared / 'VM27CameraFrame.m'),
                         ('camera-wire', camera / 'VM27CameraWire.c')]:
        obj = out / (name + '.o')
        memory = ['-fobjc-arc'] if source.suffix == '.m' else []
        run('compile-' + name, ['xcrun', '--sdk', 'iphoneos', 'clang', '-target', 'arm64e-apple-ios16.1',
            '-O2', '-Wall', '-Wextra', '-Werror', '-Werror=unguarded-availability-new', *memory,
            '-I', shared, '-c', source, '-o', obj])
        host_objects.append(obj)
    daemon = out / 'virtualmac-camera-daemon'
    guest = camera / 'guest'
    flags = ['-framework', 'Foundation', '-framework', 'IOUSBHost', '-framework', 'CoreImage',
             '-framework', 'ImageIO', '-framework', 'CoreMedia', '-framework', 'CoreVideo', '-framework', 'CoreGraphics']
    run('compile-camera-daemon', ['xcrun', '--sdk', 'macosx', 'clang', '-arch', 'arm64', '-mmacosx-version-min=15.0',
        '-fobjc-arc', '-O2', '-Wall', '-Wextra', '-Werror', '-I', camera, '-I', shared,
        '-I', root / 'VirtualMac/vz/shared-radio/guest',
        guest / 'VM27GuestCamera.m', guest / 'VM27CameraUSBHost.m', guest / 'usb_camera.c',
        shared / 'VM27CameraFrame.m', camera / 'VM27CameraWire.c', *flags, '-o', daemon])
    run('sign-camera-daemon', ['codesign', '--force', '--sign', '-', '--timestamp=none', daemon])
    run('verify-camera-daemon', ['codesign', '--verify', '--strict', daemon])
    return host_objects, daemon


BETA7_DEVELOPMENT_SOURCES = (
    "VM27RadioDevelopmentCaptureV1", "VM27RadioDevelopmentBootV1",
    "VM27RadioGuestCredentialV1", "VM27RadioDevelopmentPointerV1",
    "VM27RadioCrashDiskV1", "VM27RadioReviewGuestV1",
)


def beta7_primary_source(source):
    # Beta 7 uses the same automatic restore and boot profiles as the review
    # build. These ranges admit only the laboratory input and diagnostic paths.
    edits = (
        ('    id radioDevelopmentBootLoader = NEW("VZMacOSBootLoader");',
         '    setObj(configuration, "setBootLoader:", radioDevelopmentBootLoader);',
         '    id automaticRadioLoader = NEW("VZMacOSBootLoader");\n'
         '    if (automaticRadio26ROM && !VM27RadioUseAutomaticBootROMV1(automaticRadioLoader, automaticRadio26ROM,\n'
         '        [VZBackendRuntimeRoot() stringByAppendingPathComponent:@"parent-flat/VZ27.dylib"], error)) return nil;\n'
         '    setObj(configuration, "setBootLoader:", automaticRadioLoader);'),
        ('    if(VZIndependent27SourceRouteSelected() && [@"frame-timing" isEqualToString:action]) {',
         '\n    if([@"hibernate-vm" isEqualToString:action]) {', ''),
        ('    if (VZIndependent27SourceRouteSelected() &&\n        [@"diagnostic-ssh-enable" isEqualToString:action]) {',
         '\n    if ((VZIndependent27SourceRouteSelected() && [@"runtime-startup" isEqualToString:action]) ||', ''),
    )
    for i, (start, end, replacement) in enumerate(edits):
        if source.count(start) != 1 or source.count(end) != 1:
            raise ValueError("Beta 7 main source insertion point changed")
        begin = source.index(start)
        finish = source.index(end, begin)
        if i == 0:
            finish += len(end)
        source = source[:begin] + replacement + source[finish:]
    headers = tuple(f'/{stem}.h"' for stem in BETA7_DEVELOPMENT_SOURCES)
    source = "".join(line for line in source.splitlines(keepends=True)
                     if not (line.startswith("#import ") and line.rstrip().endswith(headers)))
    return source.replace('static BOOL VZIndependent27TryStartDiagnosticSSHV36(void)',
                          'static BOOL __attribute__((unused)) VZIndependent27TryStartDiagnosticSSHV36(void)')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--revision", type=int, default=1)
    parser.add_argument("--radio-package", type=Path, action="append", default=[],
                        help="Build-specific package directory from build-shared-radio-package-v1.py")
    parser.add_argument("--automatic-radio-package", type=Path, action="append", default=[],
                        help="Build-specific combined package for newly installed guests")
    parser.add_argument("--built-in-audio", action="store_true",
                        help="Add native speaker and microphone streams to new installations")
    parser.add_argument("--built-in-camera", action="store_true",
                        help="Stage UserHCI camera alongside the combined radio installation")
    parser.add_argument("--beta7-release", action="store_true",
                        help="Build Beta 7 using the normal library, media and setup routes")
    args = parser.parse_args()
    if args.beta7_release and not args.built_in_camera:
        parser.error('--beta7-release requires the full radio, audio and camera configuration')
    if args.automatic_radio_package and not args.radio_package:
        parser.error('--automatic-radio-package requires the regular radio catalog')
    if args.built_in_audio and not args.automatic_radio_package:
        parser.error('--built-in-audio requires automatic new-install packages')
    if args.built_in_camera and not args.built_in_audio:
        parser.error('--built-in-camera requires the built-in audio and combined radio configuration')
    root = Path(__file__).resolve().parents[3]
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    previous = root / "DeviceDiagnostics/2026-11-12-upstream-1.2.4/beta6-r2-candidate-v8"
    recipe = root / "DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/complete-dual-actual-app-v282-attempt1/candidate.json"
    metadata = json.loads(recipe.read_text())
    original_compile = next(c["argv"] for c in metadata["commands"] if c["label"] == "compile-0")
    original_source = Path(original_compile[original_compile.index("-c") + 1])
    if digest(original_source) != "5c957fa726bdf9be44d25a27ff7270941809b8cd5c372698ffe4302151ca6278":
        raise ValueError("baseline primary source changed; review the new source first")
    commands = []
    def run(label, command):
        command = list(map(str, command))
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        (out / (label + ".log")).write_bytes(result.stdout)
        commands.append({"label":label, "argv":command, "exit":result.returncode})
        (out / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")
        if result.returncode:
            raise RuntimeError(label + ": " + result.stdout.decode(errors="replace")[-3000:])
        return result.stdout
    radio = root / "VirtualMac/vz/shared-radio"
    primary = out / "VirtualMacApp_shared_radio_v1.m"
    primary.write_text('#import "' + str(radio / "host/VM27SharedRadioVZBridgeV1.h") + '"\n'
        '#import "' + str(radio / "host/VM27RadioDevelopmentCaptureV1.h") + '"\n'
        '#import "' + str(radio / "host/VM27RadioDevelopmentBootV1.h") + '"\n'
        '#import "' + str(radio / "host/VM27RadioAutomaticBoot26V1.h") + '"\n'
        '#import "' + str(radio / "host/VM27RadioGuestCredentialV1.h") + '"\n'
        '#import "' + str(radio / "host/VM27RadioDevelopmentPointerV1.h") + '"\n'
        '#import "' + str(radio / "host/VM27RadioCrashDiskV1.h") + '"\n'
        '#import "' + str(radio / "host/VM27SharedRadioBootArgumentsV1.h") + '"\n'
        '#import "' + str(radio / "host/VM27RadioReviewGuestV1.h") + '"\n'
        '#import "' + str(root / "VirtualMac/vz/host/vm27_own_uikit_ingress_profile_v1.h") + '"\n'
        + ('' if args.radio_package else '#define VM27CreateGenuineVZSSHBridgeV3 VM27CreateGenuineVZSSHBridgeV3WithSharedRadiosV1\n')
        + original_source.read_text())
    boot_marker = '    setObj(configuration, "setBootLoader:", NEW("VZMacOSBootLoader"));'
    if primary.read_text().count(boot_marker) != 1:
        raise ValueError("development boot insertion point changed")
    primary.write_text(primary.read_text().replace(boot_marker,
        '    id radioDevelopmentBootLoader = NEW("VZMacOSBootLoader");\n'
        '    if (!VM27RadioConfigureDevelopmentBootV1(radioDevelopmentBootLoader, bundlePath,\n'
        '        [VZBackendRuntimeRoot() stringByAppendingPathComponent:@"parent-flat/VZ27.dylib"], error)) return nil;\n'
        '    if (VM27RadioDevelopmentBootSelectedV1(radioDevelopmentBootLoader) &&\n'
        '        !VZIndependent27ConfigureUARTV23(configuration, error)) return nil;\n'
        '    if (VM27RadioDevelopmentBootSelectedV1(radioDevelopmentBootLoader) &&\n'
        '        !VM27RadioReviewGuestAdmittedV1(bundlePath, NO) &&\n'
        '        !VM27RadioConfigureDiagnosticUSBV1(configuration,\n'
        '            [VZBackendRuntimeRoot() stringByAppendingPathComponent:@"parent-flat/VZ27.dylib"])) return nil;\n'
        '    setObj(configuration, "setBootLoader:", radioDevelopmentBootLoader);'))
    if args.radio_package:
        if args.automatic_radio_package:
            platform_marker = '    id platform = NEW("VZMacPlatformConfiguration");'
            text = primary.read_text()
            if text.count(platform_marker) != 1:
                raise ValueError('new guest boot preparation insertion point changed')
            text = text.replace(platform_marker,
                '    NSError *automaticRadioBootError = nil;\n'
                '    NSString *automaticRadio26ROM = VM27RadioAutomaticBoot26V1(bundlePath,\n'
                '        [VZBackendRuntimeRoot() stringByAppendingPathComponent:@"Firmware27/AVPBooter.vmapple2.bin"], &automaticRadioBootError);\n'
                '    if (automaticRadioBootError) { if(error)*error=automaticRadioBootError;return nil; }\n'
                + platform_marker)
            primary.write_text(text)
        nvram_marker = '    setObj(platform, "setAuxiliaryStorage:", auxiliaryStorage);'
        if primary.read_text().count(nvram_marker) != 1:
            raise ValueError('per-guest NVRAM insertion point changed')
        boot_function = ('(automaticRadio26ROM ? VM27SharedRadioAutomatic26BootArgumentsV1 : VM27SharedRadioBluetoothBootArgumentsV1)'
                         if args.automatic_radio_package else 'VM27SharedRadioBluetoothBootArgumentsV1')
        primary.write_text(primary.read_text().replace(nvram_marker,
            '    if (VZIndependent27SourceRouteSelected() && ![options[@"SharedRadioEnabledV1"] isEqual:@NO] &&\n'
            '        !' + boot_function + '(auxiliaryStorage,\n'
            '            [VZBackendRuntimeRoot() stringByAppendingPathComponent:@"parent-flat/VZ27.dylib"], error)) return nil;\n'
            + nvram_marker))
        if args.automatic_radio_package:
            install_marker = '    self.installationOptions = options;'
            text = primary.read_text()
            if text.count(install_marker) != 1:
                raise ValueError('new-install configuration insertion point changed')
            text = text.replace(install_marker,
                '    NSMutableDictionary *radioNewGuestOptions = [NSMutableDictionary dictionaryWithDictionary:options];\n'
                '    if (VZIndependent27SourceRouteSelected()) radioNewGuestOptions[@"AutomaticRadioInstallationV1"] = @YES;\n'
                '    self.installationOptions = radioNewGuestOptions;')
            primary.write_text(text)
    if args.built_in_audio:
        primary.write_text(add_builtin_audio(primary.read_text()))
    if args.built_in_camera:
        primary.write_text(add_builtin_camera(primary.read_text()))
    marker = '    if (VZIndependent27SourceRouteSelected() &&\n        [@"guest-gui-diagnostic" isEqualToString:action]) {'
    if primary.read_text().count(marker) != 1:
        raise ValueError("development capture insertion point changed")
    primary.write_text(primary.read_text().replace(marker,
        '    if (VZIndependent27SourceRouteSelected() && [@"radio-acceptance-mouse-gatt-probe" isEqualToString:action]) {\n'
        '        if (url.user || url.password || url.port || url.fragment || url.query || url.path.length || !gVirtualMachine ||\n'
        '            gIndependent27OwnerClosePending || gIndependent27VMStateTransitionPendingV44 ||\n'
        '            ![self.window.rootViewController isKindOfClass:VZViewController.class] ||\n'
        '            ![((VZViewController *)self.window.rootViewController).activeVMBundlePath\n'
        '                isEqual:@"/var/mobile/Media/VirtualMac/Tahoe3-RadioDev.bundle"]) return NO;\n'
        '        return VM27SharedRadioRequestForVMV1(gVirtualMachine,\n'
        '            @{@"method":@"bluetooth.acceptanceMouseGATTProbe"}, ^(NSDictionary *result) {\n'
        '                NSData *json=[NSJSONSerialization dataWithJSONObject:result options:NSJSONWritingSortedKeys error:nil];\n'
        '                if(json)fprintf(stderr,"[SharedBluetoothGATTProbe] result=%s\\n",\n'
        '                    [[NSString alloc]initWithData:json encoding:NSUTF8StringEncoding].UTF8String);\n'
        '            });\n'
        '    }\n'
        '    if (VZIndependent27SourceRouteSelected() && [@"radio-crash-disk-readonly" isEqualToString:action]) {\n'
        '        if (url.user || url.password || url.port || url.fragment || url.query || url.path.length || !gVirtualMachine ||\n'
        '            gIndependent27OwnerClosePending || gIndependent27VMStateTransitionPendingV44 ||\n'
        '            ![self.window.rootViewController isKindOfClass:VZViewController.class]) return NO;\n'
        '        return VM27RadioAttachReadOnlyCrashDiskV1(gVirtualMachine,\n'
        '            ((VZViewController *)self.window.rootViewController).activeVMBundlePath,\n'
        '            [VZBackendRuntimeRoot() stringByAppendingPathComponent:@"parent-flat/VZ27.dylib"]);\n'
        '    }\n'
        '    if (VZIndependent27SourceRouteSelected() && [@"radio-guest-unlock" isEqualToString:action]) {\n'
        '        if (url.user || url.password || url.port || url.fragment || url.query || url.path.length || !gVirtualMachine ||\n'
        '            ![self.window.rootViewController isKindOfClass:VZViewController.class]) return NO;\n'
        '        VZViewController *radioController = (VZViewController *)self.window.rootViewController;\n'
        '        uint64_t expectedEpoch = gIndependent27SessionEpoch;\n'
        '        return VM27RadioReceiveGuestCredentialV1(gVirtualMachine, radioController.activeVMBundlePath,\n'
        '            ^BOOL(id expectedVM, const uint8_t *digits, size_t length) {\n'
        '                if (!pthread_main_np() || gVirtualMachine != expectedVM || expectedEpoch != gIndependent27SessionEpoch ||\n'
        '                    gIndependent27OwnerClosePending || gIndependent27VMStateTransitionPendingV44 || !gKeyboard ||\n'
        '                    ((NSInteger(*)(id,SEL))objc_msgSend)(expectedVM,S("state")) != 1 ||\n'
        '                    ((dispatch_queue_t(*)(id,SEL))objc_msgSend)(expectedVM,S("queue")) != dispatch_get_main_queue() ||\n'
        '                    ![VM27OwnUIKitIngressProfileV1 genuine27PointingAndKeyboardProfileMatches:gPointingDevice keyboard:gKeyboard]) return NO;\n'
        '                const unsigned short keyCodes[10] = {29,18,19,20,21,23,22,26,28,25};\n'
        '                NSMutableArray *events = [NSMutableArray arrayWithCapacity:(length+1)*2];\n'
        '                for (size_t i = 0; i <= length; ++i) {\n'
        '                    unsigned short code = i < length ? keyCodes[digits[i]-\'0\'] : 36;\n'
        '                    for (NSInteger type = 0; type < 2; ++type) {\n'
        '                        id event = ((id(*)(id,SEL,NSInteger,unsigned short))objc_msgSend)(\n'
        '                            m0(CLS("_VZKeyEvent"),"alloc"),S("initWithType:keyCode:"),type,code);\n'
        '                        if (!event) return NO; [events addObject:event]; [event release];\n'
        '                    }\n'
        '                }\n'
        '                ((void(*)(id,SEL,id))objc_msgSend)(gKeyboard,S("sendKeyEvents:"),events);\n'
        '                return YES;\n'
        '            });\n'
        '    }\n'
        '    if (VZIndependent27SourceRouteSelected() && [@"radio-guest-click" isEqualToString:action]) {\n'
        '        if (url.user || url.password || url.port || url.fragment || url.path.length || !gVirtualMachine ||\n'
        '            gIndependent27OwnerClosePending || gIndependent27VMStateTransitionPendingV44 ||\n'
        '            ![self.window.rootViewController isKindOfClass:VZViewController.class]) return NO;\n'
        '        NSArray *items = [NSURLComponents componentsWithURL:url resolvingAgainstBaseURL:NO].queryItems;\n'
        '        if (items.count != 2) return NO;\n'
        '        NSString *x = nil, *y = nil;\n'
        '        for (NSURLQueryItem *item in items) {\n'
        '            if ([item.name isEqual:@"x"] && !x) x = item.value;\n'
        '            else if ([item.name isEqual:@"y"] && !y) y = item.value; else return NO;\n'
        '        }\n'
        '        return VM27RadioDevelopmentClickV1(gVirtualMachine, gPointingDevice, gKeyboard,\n'
        '            ((VZViewController *)self.window.rootViewController).activeVMBundlePath, x, y);\n'
        '    }\n'
        '    if (VZIndependent27SourceRouteSelected() && [@"radio-review-install" isEqualToString:action]) {\n'
        '        if (url.user || url.password || url.port || url.fragment || url.path.length || gVirtualMachine || VZBackendIsRunActive() ||\n'
        '            ![self.window.rootViewController isKindOfClass:VZViewController.class]) return NO;\n'
        '        NSArray *items=[NSURLComponents componentsWithURL:url resolvingAgainstBaseURL:NO].queryItems;\n'
        '        if (items.count!=2) return NO;NSString *session=nil,*major=nil;\n'
        '        for (NSURLQueryItem *item in items) {\n'
        '            if ([item.name isEqual:@"session"] && !session) session=item.value;\n'
        '            else if ([item.name isEqual:@"major"] && !major) major=item.value;else return NO;\n'
        '        }\n'
        '        NSDictionary *input=VM27RadioReviewRestoreInputV1(session,major);if (!input) return NO;\n'
        '        VZViewController *reviewController=(id)self.window.rootViewController;\n'
        '        VZVMLibraryViewController *library=[self libraryController];\n'
        '        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,750*NSEC_PER_MSEC),dispatch_get_main_queue(),^{\n'
        '            if (gVirtualMachine || VZBackendIsRunActive() || self.window.rootViewController!=reviewController) return;\n'
        '            printf("[SharedRadioReview] normal visible install requested major=%s\\n",major.UTF8String);\n'
        '            [reviewController vmLibrary:library installRestoreImageAtURL:[NSURL fileURLWithPath:input[@"restoreImage"]]\n'
        '                name:input[@"name"] options:VZVMDefaultOptions()];\n'
        '        });return YES;\n'
        '    }\n'
        '    if (VZIndependent27SourceRouteSelected() && [@"radio-review-keys" isEqualToString:action]) {\n'
        '        if (url.user || url.password || url.port || url.fragment || url.query || url.path.length || !gVirtualMachine ||\n'
        '            ![self.window.rootViewController isKindOfClass:VZViewController.class]) return NO;\n'
        '        NSString *reviewBundle=((VZViewController *)self.window.rootViewController).activeVMBundlePath;\n'
        '        uint64_t reviewEpoch=gIndependent27SessionEpoch;\n'
        '        return VM27RadioReviewReceiveKeysV1(gVirtualMachine,reviewBundle,^BOOL(id expectedVM,NSArray *batch) {\n'
        '            if (!pthread_main_np() || gVirtualMachine!=expectedVM || reviewEpoch!=gIndependent27SessionEpoch ||\n'
        '                gIndependent27OwnerClosePending || gIndependent27VMStateTransitionPendingV44 || !gKeyboard ||\n'
        '                ((NSInteger(*)(id,SEL))objc_msgSend)(expectedVM,S("state"))!=1 ||\n'
        '                ![VM27OwnUIKitIngressProfileV1 genuine27PointingAndKeyboardProfileMatches:gPointingDevice keyboard:gKeyboard]) return NO;\n'
        '            NSMutableArray *events=[NSMutableArray arrayWithCapacity:batch.count];\n'
        '            for (NSArray *pair in batch) {\n'
        '                id event=((id(*)(id,SEL,NSInteger,unsigned short))objc_msgSend)(\n'
        '                    m0(CLS("_VZKeyEvent"),"alloc"),S("initWithType:keyCode:"),[pair[1]integerValue],[pair[0]unsignedShortValue]);\n'
        '                if (!event) return NO;[events addObject:event];[event release];\n'
        '            }\n'
        '            ((void(*)(id,SEL,id))objc_msgSend)(gKeyboard,S("sendKeyEvents:"),events);return YES;\n'
        '        });\n'
        '    }\n'
        '    if (VZIndependent27SourceRouteSelected() && [@"radio-guest-screen" isEqualToString:action]) {\n'
        '        if (url.user || url.password || url.port || url.fragment || url.query || url.path.length || !gVirtualMachine) {\n'
        '            fprintf(stderr, "[SharedRadioDevelopment] screen URL refused vmPresent=%d\\n", gVirtualMachine != nil); return NO;\n'
        '        }\n'
        '        BOOL captureAccepted = VM27RadioDevelopmentCaptureV1([gIndependent27GuestDisplay view]);\n'
        '        fprintf(stderr, "[SharedRadioDevelopment] screen URL accepted=%d\\n", captureAccepted);\n'
        '        return captureAccepted;\n'
        '    }\n' + marker))
    uart_budget = 'static const size_t kIndependent27UARTInputLimitV23=65536;'
    if primary.read_text().count(uart_budget) != 1:
        raise ValueError('bounded development UART budget insertion point changed')
    primary.write_text(primary.read_text().replace(uart_budget,
        'static const size_t kIndependent27UARTInputLimitV23=2097152;')
        .replace('selectedInputBytes=65536 drainingContinues=1', 'selectedInputBytes=2097152 drainingContinues=1')
        .replace('inputLimit=65536 readNonblocking=1', 'inputLimit=2097152 readNonblocking=1'))
    network_start = '    int status=VM27NativeNetworkStartV1(&owner,&descriptor);'
    if primary.read_text().count(network_start) != 1:
        raise ValueError('development network selection insertion point changed')
    primary.write_text(primary.read_text().replace(network_start,
        '    int status=VM27NativeNetworkStartWithSharedRadiosV1(&owner,&descriptor);' if args.radio_package else
        '    int status=VM27RadioDevelopmentBootSelectedV1(m0(configuration,"bootLoader"))\n'
        '        ? VM27NativeNetworkStartForRadioDevV1(&owner,&descriptor)\n'
        '        : VM27NativeNetworkStartV1(&owner,&descriptor);'))
    if args.radio_package:
        launcher_marker = '[NSBundle.mainBundle pathForResource:@"install-launcher" ofType:nil]'
        text = primary.read_text()
        if text.count(launcher_marker) != 3:
            raise ValueError('existing installer launch/cancellation call sites changed')
        primary.write_text(text.replace(launcher_marker,'VM27SharedRadioInstallationLauncherV1()'))
        attach_marker = '    VZGuestToolsAttachToVirtualMachine(gVirtualMachine);'
        close_marker = '    if (gIndependent27OwnerClosePending) return;'
        text = primary.read_text()
        if text.count(attach_marker) != 1 or text.count(close_marker) != 1:
            raise ValueError('independent radio lifecycle insertion points changed')
        text = text.replace(attach_marker,
            '    if (VZIndependent27SourceRouteSelected() && ![options[@"SharedRadioEnabledV1"] isEqual:@NO]) {\n'
            '        NSError *radioError=nil;\n'
            '        if (!VM27AttachSharedRadiosToVMV1(gVirtualMachine,\n'
            '            [VZBackendRuntimeRoot() stringByAppendingPathComponent:@"parent-flat/VZ27.dylib"], &radioError)) {\n'
            '            finishVMThreadSafe(delegate,radioError); return;\n'
            '        }\n'
            '    }\n' + attach_marker)
        text = text.replace(close_marker,close_marker+'\n'
            '    if (gVirtualMachine && VM27HasSharedRadioOwnerV1(gVirtualMachine)) {\n'
            '        gIndependent27OwnerClosePending=YES;\n'
            '        id radioVM=[gVirtualMachine retain], radioUI=[self retain];\n'
            '        NSError *radioStopError=[error retain];\n'
            '        VM27CloseSharedRadiosForVMV1(radioVM, ^(NSError *radioCloseError) {\n'
            '            NSCAssert(pthread_main_np(),@"Radio drain completes on actual main VM.queue.");\n'
            '            gIndependent27OwnerClosePending=NO;\n'
            '            if (radioCloseError || gVirtualMachine!=radioVM) {\n'
            '                VZPresentFailureReport(radioUI,VZL(@"Virtual Mac Stopped"),\n'
            '                    radioCloseError.localizedDescription ?: @"The actual radio VM changed during drain.",\n'
            '                    nil,VZFailureSupportOptionSuggestDebugLogging);\n'
            '            } else [radioUI finishVMAndShowLibraryWithError:radioStopError];\n'
            '            [radioStopError release];[radioUI release];[radioVM release];\n'
            '        });\n'
            '        return;\n'
            '    }')
        primary.write_text(text)
    compile_command = original_compile.copy()
    compile_command[compile_command.index("-c") + 1] = str(primary)
    compile_command[compile_command.index("-o") + 1] = str(out / "main.o")
    compile_command[compile_command.index("-MF") + 1] = str(out / "main.d")
    sdk = subprocess.check_output(["xcrun", "--sdk", "iphoneos", "--show-sdk-path"], text=True).strip()
    compile_command[compile_command.index("-isysroot") + 1] = sdk
    compile_command[compile_command.index("-target") + 1] = "arm64e-apple-ios16.1"
    camera = root / 'VirtualMac/vz/camera'
    camera_objects, camera_daemon = [], None
    if args.built_in_camera:
        compile_command.extend(['-I', camera, '-I', root / 'VirtualMac/vz/shared'])
        camera_objects, camera_daemon = build_camera_tools(root, out, run)
    if args.beta7_release:
        primary.write_text(beta7_primary_source(primary.read_text()))
    run("compile-main", compile_command)
    sources = [radio / name for name in ["host/VM27SharedRadioHostV1.m", "host/VM27OwnedWiFiHostV1.m",
        "host/vm27_shared_radio_host_main_v1.m", "host/VM27SharedRadioVZBridgeV1.m",
        "common/vm27_shared_radio_wire_v1.c", "host/VM27RadioDevelopmentCaptureV1.m",
        "host/VM27RadioDevelopmentBootV1.m", "host/VM27RadioAutomaticBoot26V1.m", "host/VM27RadioGuestCredentialV1.m",
        "host/VM27RadioDevelopmentPointerV1.m", "host/VM27RadioCrashDiskV1.m",
        "host/VM27SharedRadioBootArgumentsV1.m",
        "host/VM27RadioReviewGuestV1.m",
        "host/VM27SharedBluetoothHostV1.m", "host/VM27SharedBluetoothClassicHostV1.m",
        "host/VM27SharedBluetoothGATTPeerV1.m", "host/VM27SharedBluetoothPeerWorkerV1.m"]]
    if args.beta7_release:
        sources = [source for source in sources if source.stem not in BETA7_DEVELOPMENT_SOURCES]
    objects = []
    for index, source in enumerate(sources):
        obj = out / (source.stem + ".o")
        flags = ["-fobjc-arc"] if source.suffix == ".m" else []
        run("compile-radio-" + str(index), ["xcrun", "--sdk", "iphoneos", "clang",
            "-target", "arm64e-apple-ios16.1", "-O2", "-fblocks", *flags,
            "-DVM27_SHARED_RADIO_LIBRARY", "-Wall", "-Wextra", "-Werror", "-c", source, "-o", obj])
        objects.append(obj)
    network_source = root / 'VirtualMac/vz/host/vm27_native_network_v1.c'
    network_object = out / 'vm27_native_network_v1.o'
    network_headers = root / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/release-2.0.0beta5-candidate-v3/network-source-and-relink-v5/sources'
    run('compile-development-network', ['xcrun','--sdk','iphoneos','clang',
        '-target','arm64e-apple-ios16.1','-O2','-std=gnu11','-Wall','-Wextra','-Werror',
        '-I',network_headers,'-c',network_source,'-o',network_object])
    guest_tools_object = None
    guest_tools_source = None
    if args.radio_package:
        # Keep provisioning on the existing owned guest-agent connection. It
        # must work independently of SSH, user names, and the optional menu App.
        guest_recipe = next(c['argv'] for c in json.loads((previous / 'commands.json').read_text())
                            if c['label'] == 'compile-guest-provisioning').copy()
        source = Path(guest_recipe[guest_recipe.index('-c') + 1])
        text = source.read_text()
        marker = 'static void VZGuestToolsProvisionDesktop(NSUInteger attempt);'
        ready = '                    VZGuestToolsProvisionDesktop(0);'
        if text.count(marker) != 1 or text.count(ready) != 1:
            raise ValueError('owned QGA provisioning insertion points changed')
        text = text.replace(marker, '#include "' + str(radio / 'host/VM27SharedRadioProvisioningV1.inc') + '"\n' + marker)
        text = text.replace(ready,
            '                    VM27SharedRadioProvisionStartV1(generation, 0, ^{\n'
            '                        VZGuestToolsProvisionDesktop(0);\n'
            '                    });')
        if args.built_in_camera:
            camera_include = '#include "' + str(camera / 'VM27CameraProvision.inc') + '"\n'
            text = text.replace(marker, camera_include + marker)
            camera_stage = ('                    VM27SharedRadioProvisionStartV1(generation, 0, ^{\n'
                            '                        VZGuestToolsProvisionDesktop(0);\n'
                            '                    });')
            if text.count(camera_stage) != 1:
                raise ValueError('camera provisioning callback changed')
            text = text.replace(camera_stage,
                '                    VM27SharedRadioProvisionStartV1(generation, 0, ^{\n'
                '                        VM27CameraProvisionV1(generation, ^{ VZGuestToolsProvisionDesktop(0); });\n'
                '                    });')
        start_gate = '    if (!guestToolsEnabled && !removalPending) return;'
        if text.count(start_gate) != 1:
            raise ValueError('optional Guest Tools provisioning gate changed')
        text = text.replace(start_gate,
            '    if (!guestToolsEnabled && !removalPending &&\n'
            '        ![NSFileManager.defaultManager fileExistsAtPath:[NSBundle.mainBundle.resourcePath\n'
            '            stringByAppendingPathComponent:@"SharedRadio/Catalog.plist"]]) return;')
        guest_tools_source = out / 'VZGuestTools_shared_radio_provisioning_v1.m'
        guest_tools_source.write_text(text)
        guest_tools_object = out / 'guest-tools-radio.o'
        guest_recipe[guest_recipe.index('-c') + 1] = str(guest_tools_source)
        guest_recipe[guest_recipe.index('-o') + 1] = str(guest_tools_object)
        guest_recipe[guest_recipe.index('-MF') + 1] = str(out / 'guest-tools-radio.d')
        guest_recipe[guest_recipe.index('-target') + 1] = 'arm64e-apple-ios16.1'
        run('compile-radio-provisioning', guest_recipe)
    baseline_app = previous / "stage/var/jb/Applications/VirtualMacIndependent27.app"
    app = out / baseline_app.name
    if app.exists():
        raise ValueError("use a new output directory, App already exists")
    shutil.copytree(baseline_app, app)
    binary = app / "VirtualMacIndependent27"
    link = next(c["argv"] for c in json.loads((previous / "commands.json").read_text()) if c["label"] == "link-app").copy()
    old_main = original_compile[original_compile.index("-o") + 1]
    if link.count(old_main) != 1:
        raise ValueError("baseline main object not uniquely identified")
    link[link.index(old_main)] = str(out / "main.o")
    old_network = next(value for value in link if value.endswith('/35-vm27_native_network_v1.o'))
    link[link.index(old_network)] = str(network_object)
    if guest_tools_object:
        old_guest_tools = next(value for value in link if value.endswith('/8-guest-tools.o'))
        link[link.index(old_guest_tools)] = str(guest_tools_object)
        # The accepted connection now owns a retirement lease for its whole
        # lifetime. Rebuild its implementation together with the QGA caller.
        lease_source = root / 'VirtualMac/vz/host/vm27_owned_qga_connection_lease_v3.c'
        lease_object = out / 'vm27_owned_qga_connection_lease_v3.o'
        run('compile-qga-connection-lease', ['xcrun', '--sdk', 'iphoneos', 'clang',
            '-target', 'arm64e-apple-ios16.1', '-O2', '-std=gnu11',
            '-Wall', '-Wextra', '-Werror', '-c', lease_source, '-o', lease_object])
        old_lease = next(value for value in link if value.endswith('/vm27_owned_qga_connection_lease_v3.o'))
        link[link.index(old_lease)] = str(lease_object)
    link[link.index("-isysroot") + 1] = sdk
    link[link.index("-target") + 1] = "arm64e-apple-ios16.1"
    link[link.index("-o") + 1] = str(binary)
    preserved_inputs = {a:digest(Path(a)) for a in link if a.endswith(".o") and a not in
                        (str(out / "main.o"),str(network_object),str(guest_tools_object))}
    camera_frameworks = ['-framework', 'AVFoundation', '-framework', 'CoreMedia',
        '-framework', 'CoreVideo', '-framework', 'ImageIO', '-framework', 'Accelerate'] if camera_daemon else []
    run("link-app", [*link, *objects, *camera_objects, "-framework", "CoreBluetooth", "-lcompression", *camera_frameworks])
    if binary.stat().st_size > 2 * 1024 * 1024:
        raise ValueError("exceeds the existing runtime self-inspector bound")
    info_path = app / "Info.plist"
    info = plistlib.loads(info_path.read_bytes())
    info["NSBluetoothAlwaysUsageDescription"] = "Share Bluetooth discovery with the VirtualMac guest."
    info["NSBluetoothPeripheralUsageDescription"] = "Share Bluetooth discovery with the VirtualMac guest."
    if args.revision < 1:
        raise ValueError('development revision must be positive')
    if args.beta7_release:
        info.update(CFBundleShortVersionString="2.0.0beta7", CFBundleVersion="1007",
                    CFBundleDisplayName="VirtualMac 2 beta7", VirtualMacPackageRevision="1007")
        info.pop("VM27SharedRadioDevelopmentRevision", None)
    else:
        info["VM27SharedRadioDevelopmentRevision"] = args.revision
    camera_localizations = ()
    if camera_daemon:
        info['NSCameraUsageDescription'] = 'Share your iPad camera with the currently running VirtualMac guest.'
        resources = app / 'Camera'
        resources.mkdir()
        shutil.copy2(camera_daemon, resources / camera_daemon.name)
        job = resources / 'com.virtualmac.camera-v1.plist'
        job.write_bytes(plistlib.dumps(dict(Label='com.virtualmac.camera-v1',
            ProgramArguments=['/Library/PrivilegedHelperTools/com.virtualmac.CameraV1'],
            RunAtLoad=True)))
        (resources / 'Manifest.plist').write_bytes(plistlib.dumps(dict(Schema=1,
            ProgramSHA256=digest(camera_daemon), JobSHA256=digest(job))))
        camera_localizations = ('Camera', 'Share Camera', 'Resolution', 'Front Camera', 'Rear Camera',
            'Flip Horizontally', 'Allow camera access in iPadOS Settings to share it with the guest.')
    if args.built_in_audio:
        localized_keys = ("Speakers", "Turn On on Next Cold Boot", "Turn Off on Next Cold Boot",
                          "On After Next Cold Boot", "Off After Next Cold Boot",
                          "Allow microphone access in iPadOS Settings to share it with the guest.")
        for language in ("en", "zh_CN"):
            resource = Path(f"{language}.lproj/Localizable.strings")
            translations = plistlib.loads(subprocess.check_output([
                "plutil", "-convert", "xml1", "-o", "-", root / "VirtualMac/resources/Localizations" / resource,
            ]))
            with (app / resource).open("a", encoding="utf-8") as strings:
                # Some base builds already carry general strings such as Resolution.
                existing = plistlib.loads(subprocess.check_output(['plutil', '-convert', 'xml1', '-o', '-', app / resource]))
                for key in (*localized_keys, *camera_localizations):
                    if key not in existing:
                        strings.write(f"\n{json.dumps(key)} = {json.dumps(translations[key], ensure_ascii=False)};")
                strings.write("\n")
    info["MinimumOSVersion"] = "16.1"
    info_path.write_bytes(plistlib.dumps(info, sort_keys=False))
    package_hashes = {}
    if args.radio_package:
        destination = app / 'SharedRadio'
        destination.mkdir(exist_ok=False)
        merged = {'Schema':1, 'Packages':{}, 'AutomaticPackages':{}}
        package_inputs = [(p, False) for p in args.radio_package] + [(p, True) for p in args.automatic_radio_package]
        for package_argument, automatic in package_inputs:
            package = package_argument.resolve()
            catalog = plistlib.loads((package / 'Catalog.plist').read_bytes())
            if catalog.get('Schema') != 1 or len(catalog.get('Packages', {})) != 1:
                raise ValueError('requires one audited guest build per input package')
            build, entry = next(iter(catalog['Packages'].items()))
            category = 'AutomaticPackages' if automatic else 'Packages'
            if build not in ('24G90','25G83','26A5416b','26B131') or build in merged[category]:
                raise ValueError('duplicate or unaudited guest build')
            if automatic and not entry.get('CombinedInstallation'):
                raise ValueError('automatic installation requires a matching combined package')
            resource_directory = 'Automatic' + build if automatic else build
            folder = destination / resource_directory
            folder.mkdir()
            for name in ['RadioPackage.tar', 'shared-radio-package-v1']:
                path = package / name
                if not path.is_file() or path.is_symlink():
                    raise ValueError('invalid packaged radio resource')
                package_hashes[resource_directory+'/'+name] = digest(path)
                shutil.copyfile(path, folder / name)
            if (entry.get('Archive') != 'RadioPackage.tar' or
                entry.get('Installer') != 'shared-radio-package-v1' or
                entry.get('ArchiveSHA256') != package_hashes[resource_directory+'/RadioPackage.tar'] or
                entry.get('InstallerSHA256') != package_hashes[resource_directory+'/shared-radio-package-v1']):
                raise ValueError('radio package catalog hashes do not match resources')
            merged[category][build] = dict(entry,ResourceDirectory=resource_directory)
        (destination/'Catalog.plist').write_bytes(plistlib.dumps(merged))
        package_hashes['Catalog.plist'] = digest(destination/'Catalog.plist')
    entitlements = plistlib.loads((previous / "app.entitlements.plist").read_bytes())
    entitlements["com.apple.wifi.manager-access"] = True
    entitlements["com.apple.bluetooth.system"] = True
    # BluetoothManager's native discovery service additionally checks this
    # entitlement. Without it available/powered remain false even while the
    # independent CoreBluetooth scan bridge receives real BLE advertisements.
    entitlements["com.apple.BluetoothServices"] = True
    entitlements["com.apple.private.tcc.allow"] = sorted(set(entitlements.get("com.apple.private.tcc.allow", [])) | {"kTCCServiceBluetoothAlways"})
    ent = out / "app.entitlements.plist"
    ent.write_bytes(plistlib.dumps(entitlements))
    with tempfile.TemporaryDirectory(prefix="vm27-radio-app-", dir="/private/tmp") as work:
        clean = Path(work) / app.name
        shutil.copytree(app, clean)
        run("clear-xattrs", ["xattr", "-cr", clean])
        run("sign-app", ["codesign", "--force", "--sign", "-", "--timestamp=none",
            "--digest-algorithm=sha256", "--identifier", info["CFBundleIdentifier"],
            "--entitlements", ent, "--generate-entitlement-der", clean])
        run("verify-app", ["codesign", "--verify", "--strict", clean])
        for path in clean.rglob("*"):
            if path.is_file():
                shutil.copyfile(path, app / path.relative_to(clean))
    signature = run("read-cdhash", ["codesign", "-d", "--verbose=4", binary]).decode()
    cdhash = re.search(r"^CDHash=([0-9a-f]{40})$", signature, re.MULTILINE).group(1)
    if any(digest(Path(a)) != h for a,h in preserved_inputs.items()):
        raise ValueError("a preserved object changed during the build")
    manifest = {"schema":1, "app":str(app), "binarySHA256":digest(binary), "cdhash":cdhash,
        "beta7Release":args.beta7_release, "minimumIOSVersion":"16.1",
        "primarySourceSHA256":digest(original_source), "adapterSourceSHA256":digest(primary),
        "preservedBeta6R2Objects":preserved_inputs,
        "radioSources":{str(p.relative_to(root)):digest(p) for p in sources},
        "developmentNetworkSourceSHA256":digest(network_source),
        "networkIsolationSourceSHA256":digest(network_source.with_name('vm27_native_network_isolation_v1.h')),
        "oneWayNATAndPerVMPacketSockets":True,
        "hostLoopbackAccessEnabled":False,
        "utunIntranetIntegration":False,
        "developmentNetworkAddsPrivateBluetoothGuestPort":True,
        "sharedWiFiSubnet":"10.0.3.0/24",
        "transport":"genuine-VZ-host-connect-to-guest-vsock-39027",
        "nativeFrameworkProviderChanges":False, "deviceDeploymentPerformed":False,
        "nativeClassicDiscoveryServiceEntitlement":True,
        "nativeGuestWiFiInterfaceValidated":False, "nativeGuestBluetoothHCIValidated":False}
    if guest_tools_source:
        manifest.update({"firstBootProvisioningSourceSHA256":digest(guest_tools_source),
            "firstBootProvisioningImplementationSHA256":digest(radio / 'host/VM27SharedRadioProvisioningV1.inc'),
            "firstBootRadioResourceSHA256":package_hashes,
            "firstBootComponentStagingImplemented":True,
            "newGuestCombinedInstallationBuilds":sorted(merged['AutomaticPackages']),
            "qgaAcceptedSocketRetirementImplemented":True,
            "qgaConnectionLeaseSourceSHA256":digest(lease_source),
            "qgaOperationSourceSHA256":digest(root / 'VirtualMac/vz/host/vm27_owned_qga_operation_v9partial.inc'),
            "guestClockSyncSourceSHA256":digest(root / 'VirtualMac/vz/host/vm27_guest_clock_relative_v18.inc'),
            "newGuestCombinedRadioAcceptanceVerified":False,
            "firstBootRadioActivationImplemented":False})
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({k:manifest[k] for k in ["app", "binarySHA256", "cdhash"]}))


if __name__ == "__main__":
    main()
