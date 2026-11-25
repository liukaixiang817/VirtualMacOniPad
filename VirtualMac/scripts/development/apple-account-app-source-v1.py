"""Connect the saved per-install identity to the actual UIKit product source."""
import hashlib
import json
from pathlib import Path
import subprocess


def replace_library(root, out, link, run):
    old = next(a for a in link if str(a).endswith('/14-VZVMLibraryViewController_v10_hibernate.o'))
    recipe = json.loads((Path(old).parent / 'commands.json').read_text())
    args = next(row['argv'][:] for row in recipe if '-c' in row.get('argv', []) and
        row['argv'][row['argv'].index('-o') + 1] == old)
    source = root / 'VirtualMac/vz/host/portable_app_v1/host/VZVMLibraryViewController_v10_hibernate.m'
    frozen = out / 'VZVMLibraryViewController_account_v1.m'
    frozen.write_bytes(source.read_bytes())
    obj = out / 'account-library.o'
    args[args.index('-c') + 1] = frozen
    args[args.index('-o') + 1] = obj
    args[args.index('-MF') + 1] = out / 'account-library.d'
    args[args.index('-target') + 1] = 'arm64e-apple-ios16.1'
    args[args.index('-isysroot') + 1] = subprocess.check_output(
        ['xcrun', '--sdk', 'iphoneos', '--show-sdk-path'], text=True).strip()
    run('compile-account-library', args)
    if link.count(old) != 1: raise ValueError('library object not unique')
    link[link.index(old)] = str(obj)


def compile_objects(root, out, installer, run):
    manifest = json.loads((installer / 'candidate.json').read_text())
    if len(manifest['files']) != 3: raise ValueError('expected three owned installation components')
    for row in manifest['files']:
        data = Path(row['path']).read_bytes()
        if len(data) != row['bytes'] or hashlib.sha256(data).hexdigest() != row['sha256']:
            raise ValueError('signed account installer changed')
    account = root / 'VirtualMac/vz/apple-account'
    sources = [account / (name + '.m') for name in [
        'VMAppleAccountProfileV1', 'VMAppleAccountRestoreBuildV1', 'VMAppleAccountInstallationV1']]
    sources.append(Path(manifest['anchor']))
    objects = []
    for source in sources:
        obj = out / (source.stem + '.o')
        flags = ['-fobjc-arc', '-fblocks'] if source.suffix == '.m' else []
        run('compile-' + source.stem, ['xcrun', '--sdk', 'iphoneos', 'clang', '-target',
            'arm64e-apple-ios16.1', '-O2', '-Wall', '-Wextra', '-Werror', *flags,
            '-c', source, '-o', obj])
        objects.append(obj)
    return objects

def apply(source):
    def replace(old, new):
        nonlocal source
        if source.count(old) != 1:
            raise ValueError('Apple Account insertion point changed: ' + old[:100])
        source = source.replace(old, new)

    replace('#import <AVFAudio/AVFAudio.h>', '#import <AVFAudio/AVFAudio.h>\n'
        '#import "VMAppleAccountProfileV1.h"\n#import "VMAppleAccountInstallationV1.h"')
    # The same options are durable before root restore begins and after its
    # atomic bundle move. No crash window may replace the profile's MAC.
    begin = '    NSMutableDictionary *radioNewGuestOptions = [NSMutableDictionary dictionaryWithDictionary:options];'
    end = '    self.installationOptions = radioNewGuestOptions;'
    if source.count(begin) != 1 or source.count(end) != 1: raise ValueError('new VM options moved')
    a, b = source.index(begin), source.index(end)
    block = source[a:b]
    source = source[:a] + source[b:]
    marker = '    const char *launcher =\n        VM27SharedRadioInstallationLauncherV1().fileSystemRepresentation;'
    replace(marker, block + '''    NSError *identityError = nil;
    NSDictionary *accountOptions = VMAppleAccountPrepareInstallationV1(url, attemptPath,
        radioNewGuestOptions, VZIndependent27SourceRouteSelected(), &identityError);
    if (!accountOptions) {
        VZWriteInstallationAttempt(attemptPath, @"failed", @{@"Failure":identityError.localizedDescription ?: @"Identity preparation failed"});
        VZPresentFailureReport(self, VZL(@"Could Not Prepare Apple Account"),
            identityError.localizedDescription, nil, VZFailureSupportOptionNone);
        return;
    }
    [radioNewGuestOptions setDictionary:accountOptions];
    const char *launcher = (radioNewGuestOptions[VMAppleAccountProfileOptionV1] ?
        VMAppleAccountInstallationLauncherV1() : VM27SharedRadioInstallationLauncherV1()).fileSystemRepresentation;
''')
    replace('static void startVirtualMachine(UIView *container, id delegate,\n                                NSString *bundlePath,\n                                NSDictionary *options) {',
        '''static void startVirtualMachine(UIView *container, id delegate,
                                NSString *bundlePath,
                                NSDictionary *options) {
    NSError *accountBootError = nil;
    if (!VMAppleAccountPrepareBootV1(bundlePath, options, VZIndependent27SourceRouteSelected(), &accountBootError)) {
        finishVMThreadSafe(delegate, accountBootError);
        return;
    }''')
    # Save/restore would also have to restore private hypervisor policy state.
    # Pause/resume still uses its ordinary native path.
    replace('    if(VZIndependent27SourceRouteSelected())VM27HibernateBindV4(gVirtualMachine,configuration,bundlePath);',
        '    if(VZIndependent27SourceRouteSelected()) {\n'
        '        VM27HibernateBindV4(gVirtualMachine,configuration,bundlePath);\n'
        '        if (options[VMAppleAccountProfileOptionV1]) VM27HibernateSupportedV4=NO;\n'
        '    }')
    replace('        if(!mac)mac=[m0(CLS("VZMACAddress"),"randomLocallyAdministeredAddress") retain];',
        '        if (!mac && options[VMAppleAccountProfileOptionV1])\n'
        '            @throw [NSException exceptionWithName:@"VMAppleAccountInvalidMAC"\n'
        '                reason:@"The saved Apple Account network address could not be configured." userInfo:nil];\n'
        '        if(!mac)mac=[m0(CLS("VZMACAddress"),"randomLocallyAdministeredAddress") retain];')
    return source
