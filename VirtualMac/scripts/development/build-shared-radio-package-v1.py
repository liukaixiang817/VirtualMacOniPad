#!/usr/bin/env python3
"""Package reviewed, build-specific radio components for Apple-agent provisioning.

Only stages owned components. Activation and per-guest boot policy are separate
states; this package must never be labelled as functioning Wi-Fi/Bluetooth.
"""
import argparse
import hashlib
import json
from pathlib import Path
import plistlib
import shutil
import subprocess
import tarfile


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--driver', type=Path, required=True)
    parser.add_argument('--daemon', type=Path, required=True)
    parser.add_argument('--exclusive-bluetooth', type=Path,
                        help='Matching audited 15/26/27 Bluetooth build for automatic installation')
    parser.add_argument('--reuse-boot-preparation-package', type=Path,
                        help='Reuse the exact manifest-verified preparation binary from an accepted matching package')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[3]
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    package = output / 'Package'
    package.mkdir(mode=0o700)
    info = plistlib.loads((args.driver / 'Contents/Info.plist').read_bytes())
    if info.get('CFBundleIdentifier') != 'com.virtualmac.SharedRadioNativeV1':
        raise ValueError('unexpected driver identity')
    driver_manifest = json.loads((args.driver.parent / 'manifest.json').read_text())
    facts = driver_manifest['targetKernel']
    profile_major = {'24G90': 15, '25G83': 26, '26A5416b': 27}.get(facts['build'])
    if (facts['build'] not in ('24G90', '25G83', '26A5416b') or
        facts['architecture'] != 'arm64e' or not driver_manifest.get('concreteDriverPointerSignaturesMatch') or
        sha(args.driver / 'Contents/MacOS/VM27SharedRadioNativeV1') != driver_manifest['binarySHA256']):
        raise ValueError('requires an audited build-specific driver')
    daemon_manifest = json.loads((args.daemon.parent / 'manifest.json').read_text())
    if sha(args.daemon) != daemon_manifest['binarySHA256']:
        raise ValueError('relay binary does not match its build manifest')
    for source in (args.driver, args.daemon):
        if source.is_symlink() or any(p.is_symlink() for p in source.rglob('*')):
            raise ValueError('package sources must contain no symlinks')
    shutil.copytree(args.driver, package / 'VM27SharedRadioNativeV1.kext')
    shutil.copyfile(args.daemon, package / 'shared-radio-native-daemon')
    bluetooth = None
    bluetooth_module = {15: 'VM27ExclusiveBluetoothGuest15V1.dylib',
                        26: 'VM27ExclusiveBluetoothGuestV15.dylib',
                        27: 'VM27ExclusiveBluetoothGuest27V1.dylib'}[profile_major]
    prepare_component = 'radio-prepare-boot' + str(profile_major) + '-v1'
    profile_definition = '-DVM27_RADIO_GUEST_MAJOR=' + str(profile_major)
    preparation_reuse = None
    if args.reuse_boot_preparation_package:
        if not args.exclusive_bluetooth:
            raise ValueError('boot preparation reuse requires a combined package')
        baseline = args.reuse_boot_preparation_package.resolve()
        baseline_manifest = plistlib.loads((baseline / 'Package/Package.plist').read_bytes())
        baseline_receipt = json.loads((baseline / 'manifest.json').read_text())
        old_prepare = baseline / 'Package' / prepare_component
        if (baseline_manifest.get('GuestBuild') != facts['build'] or
            not baseline_manifest.get('CombinedInstallation') or old_prepare.is_symlink() or
            not old_prepare.is_file() or
            sha(old_prepare) != baseline_manifest['Files'][prepare_component]['SHA256']):
            raise ValueError('boot preparation baseline identity/hash mismatch')
        preparation_reuse = {'package': str(baseline), 'component': prepare_component,
                             'binarySHA256': sha(old_prepare),
                             'originalSourceSHA256': baseline_receipt['automaticSourcesSHA256']['VM27RadioPrepareBoot26V1.m']}
    if args.exclusive_bluetooth:
        folder = args.exclusive_bluetooth.resolve()
        bluetooth = json.loads((folder / 'manifest.json').read_text())
        if bluetooth.get('guestBuild') != facts['build'] or not bluetooth.get('beforeNativeMain'):
            raise ValueError('requires the exact matching early Bluetooth transport')
        names = [bluetooth_module, 'exclusive-early-autoload-v2',
                 'exclusive-guest-relay-v1', 'exclusive-guest-provision-v1',
                 'exclusive-hogp-service-v1']
        target = package / 'Bluetooth'
        target.mkdir(mode=0o700)
        for name in names:
            path = folder / name
            if path.is_symlink() or not path.is_file() or sha(path) != bluetooth['sha256'].get(name):
                raise ValueError('Bluetooth component does not match its build manifest: ' + name)
            shutil.copyfile(path, target / name)
        # Job definitions come from this source tree and are covered by the
        # package manifest, never discovered from an installed guest.
        for name in ['com.virtualmac.exclusive-bluetooth-autoload-v1.plist',
                     'com.virtualmac.exclusive-bluetooth-relay-v1.plist',
                     'com.virtualmac.exclusive-bluetooth-hogp-v1.plist']:
            shutil.copyfile(root / 'VirtualMac/vz/shared-radio/exclusive' / name, target / name)
        activation = package / 'radio-first-boot-v1'
        subprocess.run(['xcrun', '--sdk', 'macosx', 'clang', '-arch', 'arm64',
                        '-mmacosx-version-min=15.0', '-fobjc-arc', '-Wall', '-Wextra',
                        '-Werror', '-O2', profile_definition, '-framework', 'Foundation', '-framework', 'IOKit',
                        str(root / 'VirtualMac/vz/shared-radio/guest/VM27RadioFirstBootV1.m'),
                        '-o', str(activation)], check=True)
        subprocess.run(['codesign', '--force', '--sign', '-', '--timestamp=none',
                        str(activation)], check=True)
        for source_name, binary_name, frameworks in [
            ('VM27RadioPrepareBoot26V1.m', prepare_component, ['Foundation']),
            ('VM27RadioOwnerAuthorizationV1.m', 'radio-owner-authorization-v1', ['AppKit', 'SystemConfiguration']),
        ]:
            if preparation_reuse and binary_name == prepare_component:
                shutil.copyfile(old_prepare, package / binary_name)
                subprocess.run(['codesign', '--verify', '--strict', str(package / binary_name)], check=True)
                continue
            command = ['xcrun', '--sdk', 'macosx', 'clang', '-arch', 'arm64',
                       '-mmacosx-version-min=15.0', '-fobjc-arc', '-Wall', '-Wextra', '-Werror', '-O2', profile_definition]
            for framework in frameworks:
                command += ['-framework', framework]
            command += ['-lcompression', str(root / 'VirtualMac/vz/shared-radio/guest' / source_name),
                        '-o', str(package / binary_name)]
            subprocess.run(command, check=True)
            subprocess.run(['codesign', '--force', '--sign', '-', '--timestamp=none',
                            str(package / binary_name)], check=True)
        approval = output / 'ApprovalBuild'
        subprocess.run(['python3', str(root / 'VirtualMac/scripts/development/build-shared-radio-approved-driver-client-v1.py'),
                        '--output', str(approval), '--guest-build', facts['build'], '--driver', str(args.driver)], check=True)
        shutil.copyfile(approval / 'approved-driver-v1', package / 'radio-approve-driver-v1')
    files = {}
    for path in sorted(package.rglob('*')):
        if path.is_dir():
            path.chmod(0o700)
        elif path.is_file():
            mode = 0o700 if (path.name in ('shared-radio-native-daemon', 'VM27SharedRadioNativeV1',
                                         'radio-first-boot-v1', prepare_component,
                                         'radio-owner-authorization-v1', 'radio-approve-driver-v1') or
                            path.name.startswith('exclusive-') or path.suffix == '.dylib') else 0o600
            path.chmod(mode)
            files[str(path.relative_to(package))] = {'SHA256': sha(path), 'Mode': mode}
        else:
            raise ValueError('unsupported package entry')
    manifest = {'Schema': 1, 'GuestBuild': facts['build'], 'GuestKernelVersion': facts['kernel_version'], 'Files': files,
                'ActivationImplemented': False, 'BluetoothPairingImplemented': False}
    if bluetooth:
        manifest['CombinedInstallation'] = {
            'Schema': 1, 'GuestBuild': facts['build'],
            'DriverVersion': info['CFBundleVersion'],
            'BluetoothNativeExecutableSHA256': bluetooth['guestExecutableSHA256'],
            'BluetoothEarlyModuleSHA256': bluetooth['sha256'][bluetooth_module],
            'FirstBootCoordinator': 'radio-first-boot-v1',
            'GuestPolicyChangesAutomatic': False,
            'FirstPairingRequiresGuestRequest': True,
        }
    manifest_path = package / 'Package.plist'
    manifest_path.write_bytes(plistlib.dumps(manifest, sort_keys=True))
    manifest_path.chmod(0o600)
    helper = output / 'shared-radio-package-v1'
    source = root / 'VirtualMac/vz/shared-radio/guest/VM27SharedRadioPackageV1.m'
    commands = [
        ['xcrun', '--sdk', 'macosx', 'clang', '-arch', 'arm64', '-mmacosx-version-min=15.0',
         '-fobjc-arc', '-Wall', '-Wextra', '-Werror', '-O2', profile_definition, '-framework', 'Foundation', str(source), '-o', str(helper)],
        ['codesign', '--force', '--sign', '-', '--timestamp=none', str(helper)],
        ['codesign', '--verify', '--strict', str(helper)],
    ]
    for index, command in enumerate(commands):
        result = subprocess.run(command, capture_output=True)
        (output / f'build-{index}.log').write_bytes(result.stdout + result.stderr)
        if result.returncode:
            raise RuntimeError(result.stderr.decode(errors='replace'))
    archive = output / 'RadioPackage.tar'
    with tarfile.open(archive, 'w', format=tarfile.USTAR_FORMAT) as tar:
        for path in [package, *sorted(package.rglob('*'))]:
            entry = tar.gettarinfo(str(path), arcname=str(Path('Package') / path.relative_to(package)))
            entry.uid = entry.gid = 0
            entry.uname, entry.gname, entry.mtime = 'root', 'wheel', 0
            if path.is_file():
                with path.open('rb') as stream:
                    tar.addfile(entry, stream)
            else:
                tar.addfile(entry)
    catalog = {'Schema': 1, 'Packages': {facts['build']: {
        'Archive': 'RadioPackage.tar', 'ArchiveSHA256': sha(archive),
        'Installer': helper.name, 'InstallerSHA256': sha(helper),
        'ManifestSHA256': sha(manifest_path), 'ActivationImplemented': False,
        'CombinedInstallation': bool(bluetooth),
        'MaximumArchiveBytes': 16 * 1024 * 1024}}}
    (output / 'Catalog.plist').write_bytes(plistlib.dumps(catalog, sort_keys=True))
    (output / 'manifest.json').write_text(json.dumps({
        'schema': 1, 'guestBuild': facts['build'], 'archiveSHA256': sha(archive),
        'installerSHA256': sha(helper), 'manifestSHA256': sha(manifest_path),
        'nativeWiFiConnectionVerified': False, 'nativeBluetoothPairingImplemented': False,
        'activationImplemented': False, 'commands': commands,
        'bootPreparationReused': preparation_reuse,
        'combinedWiFiBluetoothInstallation': bool(bluetooth),
        'automaticSourcesSHA256': ({name: (preparation_reuse['originalSourceSHA256']
            if preparation_reuse and name == 'VM27RadioPrepareBoot26V1.m'
            else sha(root / 'VirtualMac/vz/shared-radio/guest' / name))
            for name in ['VM27RadioFirstBootV1.m', 'VM27RadioOwnerAuthorizationV1.m',
                         'VM27RadioFirstBootPolicyV1.h',
                         'VM27RadioGuestProfileV1.h',
                         'VM27RadioConsoleSessionV1.h',
                         'VM27RadioCompletedSetupResumeV1.h', 'VM27RadioCompletedSetupResumeV1.inc',
                         'VM27RadioOwnerChannelV2.h', 'VM27RadioOwnerGUIV2.inc',
                         'VM27RadioPrepareBoot26V1.m', 'VM27RadioGuestApprovedDriverV1.m',
                         'VM27RadioIMG4V1.inc']} if bluetooth else {}),
        'sourceSHA256': sha(source)}, indent=2) + '\n')
    print(json.dumps({'output': str(output), 'archiveBytes': archive.stat().st_size,
                      'manifestSHA256': sha(manifest_path)}))


if __name__ == '__main__':
    main()
